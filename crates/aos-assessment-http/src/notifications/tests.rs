//! Real TLS callback signature and redirect qualification.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aos_assessment::time::Timestamp;
use aos_assessment_runtime::notifications::{
    DeliveryOutcome, NotificationBodyV1, NotificationEventKind, NotificationSummaryV1,
    execute_notification,
};
use aos_contract::Sha256Digest;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;

struct Credentials {
    live: AtomicBool,
    resolutions: AtomicUsize,
}

#[async_trait::async_trait]
impl NotificationCredentials for Credentials {
    async fn authorize(
        &self,
        _: &NotificationDestinationV1,
        _: &NotificationWorkPlanV1,
    ) -> Result<()> {
        ensure!(
            self.live.load(Ordering::SeqCst),
            "fixture callback review revoked"
        );
        Ok(())
    }

    async fn resolve(&self, _: &NotificationDestinationV1) -> Result<Zeroizing<Vec<u8>>> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(vec![7; 32]))
    }
}

fn plan(destination: &NotificationDestinationV1) -> Result<NotificationWorkPlanV1> {
    let now = PhysicalClock.now()?;
    let body = NotificationBodyV1 {
        schema: "aos.assessment-notification-body/v1".into(),
        delivery_id: "delivery".into(),
        resource_scope: destination.resource_scope.clone(),
        subscription_id: "subscription".into(),
        subscription_revision: 1,
        events: vec![NotificationSummaryV1 {
            event_id: "event".into(),
            sequence: 1,
            occurred_at: now.clone(),
            kind: NotificationEventKind::ScanCompleted,
            family: None,
            issue_key: None,
            context_digest: None,
            episode: None,
            state: None,
            uncertain: false,
            assessment_digest: Some(Sha256Digest::of_bytes(b"assessment")),
        }],
    };
    Ok(NotificationWorkPlanV1 {
        schema: "aos.assessment-notification-work/v1".into(),
        deployment_id: "deployment".into(),
        issuer: "coordinator".into(),
        audience: "executor".into(),
        claim_token: "claim".into(),
        attempt: 1,
        reservation_digest: Sha256Digest::of_bytes(b"reservation"),
        destination_reference: destination.destination_reference.clone(),
        destination_digest: destination.digest()?,
        body_digest: body.digest()?,
        body,
        deadline: Timestamp::from_unix_seconds(now.unix_seconds() + 60)?,
        issued_at: now,
    })
}

#[tokio::test]
async fn actual_tls_callback_signs_exact_body_and_never_follows_private_redirects() -> Result<()> {
    for (status, expected) in [
        (204, DeliveryOutcome::Accepted),
        (302, DeliveryOutcome::PermanentFailure),
        (429, DeliveryOutcome::Retryable),
    ] {
        let certificate = rcgen::generate_simple_self_signed(vec!["receiver.example".into()])?;
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let _ = provider.clone().install_default();
        let configuration = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )
                .into(),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(configuration));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let destination = NotificationDestinationV1 {
            schema: "aos.assessment-notification-destination/v1".into(),
            destination_reference: "webhook:42".into(),
            revision: 1,
            resource_scope: "registry".into(),
            url: format!("https://receiver.example:{}/callback", address.port()),
            secret_version_reference: "callback-key-v1".into(),
            credential_fingerprint: Sha256Digest::of_bytes([7; 32]),
            expires_at: Timestamp::from_unix_seconds(PhysicalClock.now()?.unix_seconds() + 3600)?,
        };
        let work = plan(&destination)?;
        let credentials = Arc::new(Credentials {
            live: AtomicBool::new(true),
            resolutions: AtomicUsize::new(0),
        });
        let mut transport = NativeNotificationTransport::new(credentials.clone())?;
        // Only the fixture overrides DNS to its ephemeral TLS listener. The
        // production constructor pins public answers and has no such exception.
        transport.http = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve("receiver.example", address)
            .add_root_certificate(reqwest::Certificate::from_der(certificate.cert.der())?)
            .timeout(Duration::from_secs(5))
            .build()?;
        let task = tokio::spawn(async move {
            let (socket, _) =
                tokio::time::timeout(Duration::from_secs(10), listener.accept()).await??;
            let mut stream = acceptor.accept(socket).await?;
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                ensure!(header.len() < 16_384, "fixture callback header limit");
                let mut byte = [0];
                stream.read_exact(&mut byte).await?;
                header.push(byte[0]);
            }
            let header = String::from_utf8(header)?.to_ascii_lowercase();
            let value = |name: &str| -> Result<String> {
                header
                    .lines()
                    .find_map(|line| line.strip_prefix(&format!("{name}: ")))
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("fixture callback header absent"))
            };
            let count: usize = value("content-length")?.parse()?;
            ensure!(count <= 131_072, "fixture callback body limit");
            let mut body = vec![0; count];
            stream.read_exact(&mut body).await?;
            let signature = CallbackSignature {
                version: value("x-aos-signature-version")?,
                key_version: value("x-aos-signing-key-version")?,
                timestamp: Timestamp::parse(&value("x-aos-timestamp")?.to_ascii_uppercase())?,
                signature: value("x-aos-signature")?
                    .strip_prefix("sha256=")
                    .ok_or_else(|| anyhow::anyhow!("fixture signature profile"))?
                    .to_owned(),
            };
            let decoded =
                signature.verify(&body, "callback-key-v1", &[7; 32], &PhysicalClock.now()?)?;
            ensure!(
                value("x-aos-delivery-id")? == decoded.delivery_id,
                "fixture delivery header differs from signed body"
            );
            stream.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Length: 0\r\nLocation: https://127.0.0.1/private\r\nRetry-After: 86400\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            stream.shutdown().await?;
            Ok::<_, anyhow::Error>(decoded)
        });
        let receipt = execute_notification(&transport, &PhysicalClock, &destination, &work).await?;
        assert_eq!(receipt.outcome, expected);
        assert_eq!(receipt.status, Some(status));
        assert_eq!(task.await??, work.body);
        assert_eq!(credentials.resolutions.load(Ordering::SeqCst), 1);
        credentials.live.store(false, Ordering::SeqCst);
        assert!(
            transport
                .sign_callback(&destination, &work, &work.body.to_bytes()?)
                .await
                .is_err()
        );
        assert_eq!(credentials.resolutions.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
