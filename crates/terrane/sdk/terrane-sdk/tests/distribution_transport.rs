//! Exercises native Distribution transport with actual sockets and TLS handshakes.
//!
//! Fixture services qualify transport only, without backend or authorization claims.

#![cfg(all(feature = "tokio", not(target_arch = "wasm32")))]

#[path = "distribution_transport/fixture.rs"]
mod fixture;

use buffa::Message;
use fixture::{Services, limits};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use terrane_sdk::wire::{
    transport::{DistributionTransport, TlsIdentity, TransportError},
    v1,
};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

struct Running {
    address: std::net::SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    worker: tokio::task::JoinHandle<Result<(), TransportError>>,
}

impl Running {
    fn start(transport: DistributionTransport) -> Self {
        let address = transport.local_addr();
        let (shutdown, signal) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(transport.serve(async {
            let _ = signal.await;
        }));
        Self {
            address,
            shutdown,
            worker,
        }
    }

    async fn stop(self) -> TestResult {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(3), self.worker).await???;
        Ok(())
    }
}

async fn transport(
    services: Arc<Services>,
    tls: Option<TlsIdentity>,
) -> Result<DistributionTransport, TestError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    Ok(DistributionTransport::from_listener(
        listener,
        services.clone(),
        services.clone(),
        services,
        tls,
        limits(),
    )?)
}

fn request() -> v1::HasRequest {
    v1::HasRequest {
        hashes: [[7; 32], [8; 32], [7; 32]]
            .into_iter()
            .map(|hash| v1::Hash {
                value: hash.to_vec(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

#[tokio::test]
async fn loopback_http1_json_registers_every_mandatory_method() -> TestResult {
    let services = Arc::new(Services::default());
    let transport = transport(services.clone(), None).await?;
    assert_eq!(transport.procedures().len(), 18);
    assert!(
        transport
            .procedures()
            .iter()
            .any(|path| path == "/terrane.v1.ContentService/PutPack")
    );
    assert!(
        transport
            .procedures()
            .iter()
            .any(|path| path == "/terrane.v1.RefService/WatchRefs")
    );
    assert!(
        transport
            .procedures()
            .iter()
            .any(|path| path == "/terrane.v1.TierService/Capabilities")
    );
    let running = Running::start(transport);
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(3))
        .build()?;
    let response = client
        .post(format!(
            "http://{}/terrane.v1.ContentService/Has",
            running.address
        ))
        .header("connect-protocol-version", "1")
        .json(&request())
        .send()
        .await?;
    assert_eq!(response.version(), reqwest::Version::HTTP_11);
    assert!(response.status().is_success());
    let body: v1::HasResponse = response.json().await?;
    assert_eq!(body.present_bitmap, [5]);
    assert_eq!(services.calls.load(Ordering::SeqCst), 1);
    running.stop().await
}

#[tokio::test]
async fn loopback_http2_connect_and_grpc_preserve_protobuf_frames() -> TestResult {
    let services = Arc::new(Services::default());
    let running = Running::start(transport(services.clone(), None).await?);
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(3))
        .build()?;
    let url = format!("http://{}/terrane.v1.ContentService/Has", running.address);
    let encoded = request().encode_to_vec();
    let response = client
        .post(&url)
        .header("content-type", "application/proto")
        .header("connect-protocol-version", "1")
        .body(encoded.clone())
        .send()
        .await?;
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert!(response.status().is_success());
    assert_eq!(
        v1::HasResponse::decode_from_slice(&response.bytes().await?)?.present_bitmap,
        [5]
    );

    let response = client
        .post(&url)
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .body(frame(&encoded))
        .send()
        .await?;
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert!(response.status().is_success());
    let bytes = response.bytes().await?;
    assert_eq!(
        bytes.as_ref(),
        frame(
            &v1::HasResponse {
                present_bitmap: vec![5],
                ..Default::default()
            }
            .encode_to_vec()
        )
    );
    assert_eq!(services.calls.load(Ordering::SeqCst), 2);
    running.stop().await
}

#[allow(clippy::unwrap_used)]
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut framed = vec![0];
    framed.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    framed.extend(bytes);
    framed
}

#[tokio::test]
async fn loopback_grpc_web_has_data_and_success_trailer() -> TestResult {
    let services = Arc::new(Services::default());
    let running = Running::start(transport(services.clone(), None).await?);
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(3))
        .build()?;
    let response = client
        .post(format!(
            "http://{}/terrane.v1.ContentService/Has",
            running.address
        ))
        .header("content-type", "application/grpc-web+proto")
        .body(frame(&request().encode_to_vec()))
        .send()
        .await?;
    assert!(response.status().is_success());
    let bytes = response.bytes().await?;
    let expected = frame(
        &v1::HasResponse {
            present_bitmap: vec![5],
            ..Default::default()
        }
        .encode_to_vec(),
    );
    assert!(bytes.starts_with(&expected));
    let trailer = &bytes[expected.len()..];
    assert_eq!(trailer[0], 0x80);
    assert_eq!(
        u32::from_be_bytes(trailer[1..5].try_into()?) as usize,
        trailer.len() - 5
    );
    assert!(std::str::from_utf8(&trailer[5..])?.contains("grpc-status: 0"));
    assert_eq!(services.calls.load(Ordering::SeqCst), 1);
    running.stop().await
}

#[tokio::test]
async fn tls13_serves_both_http_versions_and_refuses_tls12() -> TestResult {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let der = certificate.cert.der().to_vec();
    let identity =
        TlsIdentity::from_der(vec![der.clone()], certificate.signing_key.serialize_der())?;
    let services = Arc::new(Services::default());
    let running = Running::start(transport(services.clone(), Some(identity)).await?);
    let url = format!(
        "https://localhost:{}/terrane.v1.ContentService/Has",
        running.address.port()
    );
    for http2 in [false, true] {
        let builder = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_der(&der)?)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .timeout(Duration::from_secs(3));
        let client = if http2 {
            builder.http2_prior_knowledge()
        } else {
            builder.http1_only()
        }
        .build()?;
        let response = client
            .post(&url)
            .header("connect-protocol-version", "1")
            .json(&request())
            .send()
            .await?;
        assert_eq!(
            response.version(),
            if http2 {
                reqwest::Version::HTTP_2
            } else {
                reqwest::Version::HTTP_11
            }
        );
        assert!(response.status().is_success());
        assert_eq!(
            response.json::<v1::HasResponse>().await?.present_bitmap,
            [5]
        );
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(der))?;
    let tls12 = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let old_client = reqwest::Client::builder()
        .use_preconfigured_tls(tls12)
        .timeout(Duration::from_secs(3))
        .build()?;
    assert!(old_client.post(&url).json(&request()).send().await.is_err());
    assert_eq!(services.calls.load(Ordering::SeqCst), 2);
    running.stop().await
}

#[tokio::test]
async fn rejects_remote_plaintext_invalid_resources_and_malformed_identity() -> TestResult {
    let services = Arc::new(Services::default());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    assert!(matches!(
        DistributionTransport::from_listener(
            listener,
            services.clone(),
            services.clone(),
            services.clone(),
            None,
            limits()
        ),
        Err(TransportError::PlaintextRemote)
    ));
    for field in 0..8 {
        let mut invalid = limits();
        match field {
            0 => invalid.max_message_bytes = 0,
            1 => invalid.max_request_bytes = 1,
            2 => invalid.max_element_memory = usize::MAX,
            3 => invalid.max_concurrent_streams = 0,
            4 => invalid.handshake_timeout = Duration::ZERO,
            5 => invalid.header_timeout = Duration::ZERO,
            6 => invalid.request_timeout = Duration::ZERO,
            _ => invalid.request_timeout = Duration::MAX,
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        assert!(matches!(
            DistributionTransport::from_listener(
                listener,
                services.clone(),
                services.clone(),
                services.clone(),
                None,
                invalid
            ),
            Err(TransportError::Limits)
        ));
    }
    assert!(matches!(
        TlsIdentity::from_der(Vec::new(), vec![0]),
        Err(TransportError::PrivateKey)
    ));
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    assert!(matches!(
        TlsIdentity::from_der(vec![vec![0]], key.signing_key.serialize_der()),
        Err(TransportError::Tls(_))
    ));
    assert_eq!(services.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn whole_stream_deadline_releases_a_pending_response_source() -> TestResult {
    let services = Arc::new(Services::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut bounded = limits();
    bounded.request_timeout = Duration::from_millis(100);
    let server = DistributionTransport::from_listener(
        listener,
        services.clone(),
        services.clone(),
        services.clone(),
        None,
        bounded,
    )?;
    let running = Running::start(server);
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?
        .post(format!(
            "http://{}/terrane.v1.ContentService/GetRange",
            running.address
        ))
        .header("content-type", "application/connect+proto")
        .header("connect-protocol-version", "1")
        .body(frame(&v1::GetRangeRequest::default().encode_to_vec()))
        .send()
        .await?;
    assert!(response.status().is_success());
    let bytes = response.bytes().await?;
    assert!(
        bytes
            .windows(b"first frame".len())
            .any(|window| window == b"first frame")
    );
    assert!(
        bytes
            .windows(b"deadline_exceeded".len())
            .any(|window| window == b"deadline_exceeded")
    );
    assert!(services.dropped_stream.load(Ordering::SeqCst));
    running.stop().await
}
