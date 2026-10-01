//! Actual HTTP response accounting and original-deadline cancellation.

use crate::storage_work::RemoteStorageWorkClient;
use aos_hub_core::{
    mirror_guard::MirrorGuardIssuer,
    oci_projection::{guard::*, OciDocumentProjection},
    storage_work::{StorageObjectIdentity, StorageWorkKey},
};
use aos_oci_types::{Annotations, Descriptor, MediaType, Sha256Digest};
use axum::{
    body::{Body, Bytes},
    http::HeaderMap,
    response::Response,
    routing::post,
    Router,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use tracing::{
    field::{Field, Visit},
    instrument::WithSubscriber as _,
    Subscriber,
};
use tracing_subscriber::{layer::SubscriberExt as _, Layer};

type Fields = BTreeMap<String, String>;
#[derive(Clone, Default)]
struct Events {
    rows: Arc<Mutex<Vec<Fields>>>,
    observed: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}
#[derive(Default)]
struct Visitor(Fields);
impl Visit for Visitor {
    fn record_str(&mut self, f: &Field, v: &str) {
        self.0.insert(f.name().into(), v.into());
    }
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        self.0.insert(f.name().into(), format!("{v:?}"));
    }
}
impl<S: Subscriber> Layer<S> for Events {
    fn on_event(&self, e: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut v = Visitor::default();
        e.record(&mut v);
        if v.0
            .get("message")
            .is_some_and(|m| m == "OCI projection response chunk observed")
        {
            if let Some(sender) = self.observed.lock().unwrap().take() {
                let _ = sender.send(());
            }
        }
        self.rows.lock().unwrap().push(v.0);
    }
}
impl Events {
    fn exchange(&self) -> Fields {
        let rows = self.rows.lock().unwrap();
        let found: Vec<_> = rows
            .iter()
            .filter(|r| {
                r.get("message")
                    .is_some_and(|m| m == "hybrid storage exchange accounting")
            })
            .collect();
        assert_eq!(found.len(), 1, "{rows:?}");
        found[0].clone()
    }
}
fn fixture() -> (OciProjectionLookup, StorageWorkKey, OciProjectionReply) {
    let bytes = b"{\"schemaVersion\":2,\"manifests\":[]}";
    let descriptor = Descriptor {
        media_type: MediaType::OciImageIndex,
        digest: Sha256Digest::digest(bytes),
        size: bytes.len() as u64,
        urls: vec![],
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    };
    let now = aos_hub_core::clock::now_unix_secs() as u64;
    let request = OciProjectionLookup {
        version: 1,
        protected_profile_digest: "c".repeat(64),
        deployment_id: "exchange-deployment".into(),
        issuer: MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "controlled-script".into(),
        },
        clock_uncertainty_seconds: 1,
        key: "registry/oci/blobs/index".into(),
        descriptor,
        admission: None,
        nonce: "b".repeat(64),
        issued_at: now,
        expires_at: now + 30,
    };
    let reply = OciProjectionReply {
        request: request.clone(),
        object: StorageObjectIdentity {
            key: request.key.clone(),
            size: bytes.len() as u64,
            etag: "\"stored-etag\"".into(),
            provider_version: Some("stored-version".into()),
        },
        projection: OciDocumentProjection::from_stored_bytes(&request.descriptor, bytes).unwrap(),
        observed_at: now + 1,
    };
    (request, StorageWorkKey::new([17; 32]).unwrap(), reply)
}
async fn serve(app: Router) -> (RemoteStorageWorkClient, String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = RemoteStorageWorkClient::new(
        "https://worker.example",
        "exchange-deployment".into(),
        &[18; 32],
    )
    .unwrap();
    (client, origin, server)
}

#[tokio::test]
async fn success_and_bad_signature_account_exact_offered_and_observed_bytes() {
    for bad_signature in [false, true] {
        let (request, key, reply) = fixture();
        let signer = if bad_signature {
            StorageWorkKey::new([19; 32]).unwrap()
        } else {
            key.clone()
        };
        let signed = sign_oci_projection_reply(&signer, &reply).unwrap();
        let expected = signed.body.len();
        let app = Router::new().route(
            OCI_PROJECTION_PATH,
            post(move |body: Bytes| {
                let body_bytes = signed.body.clone();
                let signature = signed.signature.clone();
                async move {
                    assert!(!body.is_empty());
                    let mut headers = HeaderMap::new();
                    headers.insert(OCI_PROJECTION_SIGNATURE_HEADER, signature.parse().unwrap());
                    (headers, body_bytes)
                }
            }),
        );
        let (client, origin, server) = serve(app).await;
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let result = client
            .exchange_oci_projection(&origin, &key, &request)
            .with_subscriber(subscriber)
            .await;
        server.abort();
        assert_eq!(result.is_err(), bad_signature);
        let e = events.exchange();
        assert_eq!(e["operation"], "OciDocumentProjection");
        assert_eq!(e["exchange_attempts"], "1");
        assert_eq!(
            e["offered_plan_bytes"],
            sign_oci_projection_lookup(&key, &request)
                .unwrap()
                .body
                .len()
                .to_string()
        );
        assert_eq!(e["observed_body_bytes"], expected.to_string());
        assert_eq!(
            e["outcome"],
            if bad_signature {
                "invalid_result"
            } else {
                "success"
            }
        );
    }
}
fn partial_response() -> Response {
    let mut first = true;
    let stream = futures_util::stream::poll_fn(move |_| {
        if first {
            first = false;
            Poll::Ready(Some(Ok::<_, std::io::Error>(Bytes::from_static(b"abc"))))
        } else {
            Poll::Pending
        }
    });
    Response::builder()
        .header(OCI_PROJECTION_SIGNATURE_HEADER, "unused-signature")
        .body(Body::from_stream(stream))
        .unwrap()
}

#[tokio::test]
async fn caller_cancellation_preserves_bytes_already_observed() {
    let (request, key, _) = fixture();
    let app = Router::new().route(OCI_PROJECTION_PATH, post(|| async { partial_response() }));
    let (client, origin, server) = serve(app).await;
    let events = Events::default();
    let (sender, observed) = tokio::sync::oneshot::channel();
    *events.observed.lock().unwrap() = Some(sender);
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let mut future = Box::pin(
        client
            .exchange_oci_projection(&origin, &key, &request)
            .with_subscriber(subscriber),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut future => panic!("unexpected result {result:?}"),
            result = observed => result.unwrap(),
        }
    })
    .await
    .unwrap();
    drop(future);
    server.abort();
    let e = events.exchange();
    assert_eq!(e["outcome"], "cancelled");
    assert_eq!(e["observed_body_bytes"], "3");
    assert_eq!(
        e["offered_plan_bytes"],
        sign_oci_projection_lookup(&key, &request)
            .unwrap()
            .body
            .len()
            .to_string()
    );
}

#[tokio::test]
async fn stalled_response_is_cut_off_by_the_original_deadline() {
    let (mut request, key, _) = fixture();
    request.expires_at = request.issued_at + 3;
    let app = Router::new().route(OCI_PROJECTION_PATH, post(|| async { partial_response() }));
    let (client, origin, server) = serve(app).await;
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let started = std::time::Instant::now();
    assert!(client
        .exchange_oci_projection(&origin, &key, &request)
        .with_subscriber(subscriber)
        .await
        .is_err());
    server.abort();
    assert!(started.elapsed() < Duration::from_secs(5));
    let e = events.exchange();
    assert_eq!(e["observed_body_bytes"], "3");
    assert_ne!(e["outcome"], "success");
    assert_eq!(e["exchange_attempts"], "1");
}

#[tokio::test]
async fn rejected_status_counts_offered_bytes_without_consuming_error_contents() {
    let (request, key, _) = fixture();
    let private_body = "controlled unread response contents";
    let app = Router::new().route(
        OCI_PROJECTION_PATH,
        post(move || async move { (axum::http::StatusCode::CONFLICT, private_body) }),
    );
    let (client, origin, server) = serve(app).await;
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    assert!(client
        .exchange_oci_projection(&origin, &key, &request)
        .with_subscriber(subscriber)
        .await
        .is_err());
    server.abort();
    let event = events.exchange();
    assert_eq!(event["outcome"], "http_rejected");
    assert_eq!(
        event["offered_plan_bytes"],
        sign_oci_projection_lookup(&key, &request)
            .unwrap()
            .body
            .len()
            .to_string()
    );
    assert_eq!(event["observed_body_bytes"], "0");
    assert_eq!(event["discarded_status_responses"], "1");
    assert!(!format!("{:?}", events.rows.lock().unwrap()).contains(private_body));
}
