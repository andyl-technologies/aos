//! Value-free custody of opted-in Direct authority HTTP exchanges.
//!
//! Only `HUB_NATIVE_DIRECT_CONTROL_OBSERVE=1` enables these records and the
//! non-authorizing call-ID header. Missing observation never changes admission.
//!
//! An offered image is not delivery. Complete reply EOF is not authentication:
//! existing callers verify reply MACs after this transport returns. Current SQL
//! and whole Native outgoing coverage remain independent observations.
//!
//! ```text
//! direct_control_sender_observed {version,state,route,transportCallId,
//!   constructorSourceSha256,nonceSha256,offeredRequestSha256,
//!   offeredRequestBytes,endpointScheme,replyStatus,exposedReplySha256,
//!   exposedReplyBytes,replyEof,outcome,observedAtUnixMicros,
//!   replyMacAuthentication:null,finalSqlAuthority:null}
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use aos_hub_core::direct_upload::{
    DIRECT_AUTHORITY_LOOKUP_PATH, DIRECT_FINAL_GUARD_PATH, MAX_DIRECT_CAPABILITY_BYTES,
    MAX_DIRECT_CONTROL_BYTES,
};
use aos_hub_core::storage_work::STORAGE_CAPABILITIES_PATH;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub(super) const CALL_ID_HEADER: &str = "x-aos-storage-call-id";
const FLAG: &str = "HUB_NATIVE_DIRECT_CONTROL_OBSERVE";

pub(super) fn enabled() -> bool {
    configured(std::env::var(FLAG).ok().as_deref())
}

fn configured(value: Option<&str>) -> bool {
    value == Some("1")
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    version: u8,
    state: &'static str,
    route: String,
    transport_call_id: String,
    constructor_source_sha256: String,
    nonce_sha256: String,
    offered_request_sha256: String,
    offered_request_bytes: String,
    endpoint_scheme: String,
    reply_status: Option<u16>,
    exposed_reply_sha256: String,
    exposed_reply_bytes: String,
    reply_eof: bool,
    outcome: &'static str,
    observed_at_unix_micros: Option<String>,
    reply_mac_authentication: Option<bool>,
    final_sql_authority: Option<bool>,
}

pub(super) struct Observation {
    record: Record,
    exposed: Sha256,
    exposed_bytes: u64,
    offered: bool,
    dispatcher: tracing::Dispatch,
    span: tracing::Span,
}

impl Observation {
    pub(super) fn new(
        enabled: bool,
        route: &str,
        nonce: &str,
        body: &[u8],
        origin: &str,
    ) -> Option<Self> {
        let maximum = match route {
            STORAGE_CAPABILITIES_PATH => MAX_DIRECT_CAPABILITY_BYTES,
            DIRECT_AUTHORITY_LOOKUP_PATH | DIRECT_FINAL_GUARD_PATH => MAX_DIRECT_CONTROL_BYTES,
            _ => return None,
        };
        if !enabled
            || body.len() > maximum
            || nonce.len() != 64
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let origin = url::Url::parse(origin).ok()?;
        if !matches!(origin.scheme(), "http" | "https") {
            return None;
        }
        Some(Self {
            record: Record {
                version: 1,
                state: "offered",
                route: route.into(),
                transport_call_id: uuid::Uuid::new_v4().simple().to_string(),
                constructor_source_sha256: constructor_source_sha256(),
                nonce_sha256: hex::encode(Sha256::digest(nonce.as_bytes())),
                offered_request_sha256: hex::encode(Sha256::digest(body)),
                offered_request_bytes: body.len().to_string(),
                endpoint_scheme: origin.scheme().into(),
                reply_status: None,
                exposed_reply_sha256: hex::encode(Sha256::digest([])),
                exposed_reply_bytes: "0".into(),
                reply_eof: false,
                outcome: "offered",
                observed_at_unix_micros: None,
                reply_mac_authentication: None,
                final_sql_authority: None,
            },
            exposed: Sha256::new(),
            exposed_bytes: 0,
            offered: false,
            dispatcher: tracing::dispatcher::get_default(Clone::clone),
            span: tracing::Span::current(),
        })
    }

    pub(super) fn call_id(&self) -> &str {
        &self.record.transport_call_id
    }

    pub(super) fn offered(&mut self) {
        self.offered = true;
        self.emit();
        self.record.state = "terminal";
        self.record.outcome = "cancelled";
    }

    pub(super) fn response(&mut self, status: u16) {
        self.record.reply_status = Some(status);
    }

    pub(super) fn exposed(&mut self, bytes: &[u8]) {
        self.exposed.update(bytes);
        self.exposed_bytes = self.exposed_bytes.saturating_add(bytes.len() as u64);
    }

    pub(super) fn finish(&mut self, outcome: &'static str) {
        self.record.outcome = outcome;
    }

    pub(super) fn eof(&mut self) {
        self.record.reply_eof = true;
        self.finish("reply_eof_unverified");
    }

    fn emit(&self) {
        let mut record = self.record.clone();
        record.exposed_reply_sha256 = hex::encode(self.exposed.clone().finalize());
        record.exposed_reply_bytes = self.exposed_bytes.to_string();
        record.observed_at_unix_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|time| time.as_micros().to_string());
        let Ok(encoded) = serde_json::to_string(&record) else {
            return;
        };
        if encoded.len() > 4096 {
            return;
        }
        let _subscriber = tracing::dispatcher::set_default(&self.dispatcher);
        let _span = self.span.enter();
        tracing::info!("direct_control_sender_observed {encoded}");
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        if self.offered {
            self.emit();
        }
    }
}

fn constructor_source_sha256() -> String {
    let mut digest = Sha256::new();
    digest.update(b"aos.native.direct-control-constructor.v1\0");
    let sources: [(&str, &[u8]); 6] = [
        (
            "crates/aos-hub/src/direct_upload/authority/transport.rs",
            include_bytes!("../transport.rs"),
        ),
        (
            "crates/aos-hub/src/direct_upload/authority/transport/observation.rs",
            include_bytes!("observation.rs"),
        ),
        (
            "crates/aos-hub-core/src/direct_upload/capabilities_wire.rs",
            include_bytes!("../../../../../aos-hub-core/src/direct_upload/capabilities_wire.rs"),
        ),
        (
            "crates/aos-hub-core/src/direct_upload/authority_lookup.rs",
            include_bytes!("../../../../../aos-hub-core/src/direct_upload/authority_lookup.rs"),
        ),
        (
            "crates/aos-hub-core/src/direct_upload/final_guard.rs",
            include_bytes!("../../../../../aos-hub-core/src/direct_upload/final_guard.rs"),
        ),
        (
            "crates/aos-hub-core/src/direct_upload/wire.rs",
            include_bytes!("../../../../../aos-hub-core/src/direct_upload/wire.rs"),
        ),
    ];
    for (name, bytes) in sources {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use aos_hub_core::direct_upload::{
        DirectStorageCapabilitiesRequest, WireInteger, sign_direct_storage_capabilities_request,
        verify_direct_storage_capabilities_request,
    };
    use aos_hub_core::storage_work::{STORAGE_WORK_SIGNATURE_HEADER, StorageWorkKey};
    use axum::{body::Bytes, http::HeaderMap, routing::post};
    use serde_json::Value;
    use tracing::{
        Subscriber,
        field::{Field, Visit},
        instrument::WithSubscriber as _,
    };
    use tracing_subscriber::{Layer, layer::SubscriberExt as _};

    use super::*;

    const KEY: &[u8] = b"direct-control-observation-test-key";

    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<Value>>>);

    impl<S: Subscriber> Layer<S> for Events {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Message(Option<String>);

            impl Visit for Message {
                fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                    if field.name() == "message" {
                        self.0 = Some(format!("{value:?}"));
                    }
                }
            }

            let mut message = Message(None);
            event.record(&mut message);
            if let Some(encoded) = message.0.and_then(|text| {
                text.strip_prefix("direct_control_sender_observed ")
                    .map(str::to_owned)
            }) {
                self.0
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str(&encoded).unwrap());
            }
        }
    }

    fn request() -> DirectStorageCapabilitiesRequest {
        let now = aos_hub_core::clock::now_unix_secs() as u64;
        DirectStorageCapabilitiesRequest {
            version: 2,
            deployment_id: "observation-deployment".into(),
            executor_public_origin: "https://executor.example".into(),
            request_nonce: "1".repeat(64),
            issued_at: WireInteger::new(now),
            expires_at: WireInteger::new(now + 30),
            managed: true,
            external_selectors: Vec::new(),
        }
    }

    #[test]
    fn flag_and_malformed_context_omit_observation_without_global_environment_changes() {
        assert!(!configured(None));
        assert!(!configured(Some("true")));
        assert!(!configured(Some("0")));
        assert!(configured(Some("1")));
        let nonce = "1".repeat(64);
        assert!(
            Observation::new(
                false,
                STORAGE_CAPABILITIES_PATH,
                &nonce,
                b"body",
                "https://executor.example"
            )
            .is_none()
        );
        assert!(
            Observation::new(
                true,
                "/different",
                &nonce,
                b"body",
                "https://executor.example"
            )
            .is_none()
        );
        assert!(
            Observation::new(
                true,
                STORAGE_CAPABILITIES_PATH,
                "bad",
                b"body",
                "https://executor.example"
            )
            .is_none()
        );
        assert!(
            Observation::new(
                true,
                STORAGE_CAPABILITIES_PATH,
                &nonce,
                &vec![0; MAX_DIRECT_CAPABILITY_BYTES + 1],
                "https://executor.example"
            )
            .is_none()
        );
    }

    async fn exchange(observe: bool) -> (Vec<Value>, Vec<u8>, Option<String>) {
        let original = request();
        let signed =
            sign_direct_storage_capabilities_request(&StorageWorkKey::new(KEY).unwrap(), &original)
                .unwrap();
        let body = signed.body.clone();
        let expected = original.clone();
        let received = Arc::new(Mutex::new(None));
        let retained = received.clone();
        let app = axum::Router::new().route(
            STORAGE_CAPABILITIES_PATH,
            post(move |headers: HeaderMap, bytes: Bytes| {
                let retained = retained.clone();
                let expected = expected.clone();
                async move {
                    let decoded = verify_direct_storage_capabilities_request(
                        &StorageWorkKey::new(KEY).unwrap(),
                        headers[STORAGE_WORK_SIGNATURE_HEADER].to_str().unwrap(),
                        &bytes,
                        &expected.deployment_id,
                        &expected.executor_public_origin,
                        u64::try_from(aos_hub_core::clock::now_unix_secs()).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(decoded, expected);
                    *retained.lock().unwrap() = Some((
                        bytes.to_vec(),
                        headers
                            .get(CALL_ID_HEADER)
                            .map(|value| value.to_str().unwrap().to_owned()),
                    ));
                    (
                        [(STORAGE_WORK_SIGNATURE_HEADER, "reply-signature")],
                        "reply",
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let result = super::super::post_exchange(
            &reqwest::Client::new(),
            &origin,
            STORAGE_CAPABILITIES_PATH,
            STORAGE_WORK_SIGNATURE_HEADER,
            signed,
            MAX_DIRECT_CAPABILITY_BYTES,
            &original.request_nonce,
            observe,
        )
        .with_subscriber(subscriber)
        .await
        .unwrap();
        server.abort();
        let (actual, call) = received.lock().unwrap().take().unwrap();
        assert_eq!(actual, body);
        assert_eq!(result, ("reply-signature".into(), b"reply".to_vec()));
        let rows = events.0.lock().unwrap().clone();
        (rows, body, call)
    }

    #[tokio::test]
    async fn disabled_actual_exchange_keeps_signed_body_and_headers_without_events() {
        let (rows, _, call) = exchange(false).await;
        assert!(rows.is_empty());
        assert!(call.is_none());
    }

    #[tokio::test]
    async fn enabled_actual_exchange_keeps_mac_bytes_and_records_unverified_eof() {
        let (rows, body, call) = exchange(true).await;
        assert_eq!(rows.len(), 2);
        let offered = &rows[0];
        let terminal = &rows[1];
        assert_eq!(offered["state"], "offered");
        assert_eq!(offered["transportCallId"], call.unwrap());
        assert_eq!(
            offered["offeredRequestSha256"],
            hex::encode(Sha256::digest(&body))
        );
        assert_eq!(offered["offeredRequestBytes"], body.len().to_string());
        assert_eq!(terminal["transportCallId"], offered["transportCallId"]);
        assert_eq!(
            terminal["exposedReplySha256"],
            hex::encode(Sha256::digest(b"reply"))
        );
        assert_eq!(terminal["exposedReplyBytes"], "5");
        assert_eq!(terminal["replyEof"], true);
        assert_eq!(terminal["outcome"], "reply_eof_unverified");
        assert!(terminal["replyMacAuthentication"].is_null());
        assert!(terminal["finalSqlAuthority"].is_null());
        let text = serde_json::to_string(&rows).unwrap();
        assert!(!text.contains("reply-signature"));
        assert!(!text.contains(std::str::from_utf8(KEY).unwrap()));
    }

    #[tokio::test]
    async fn actual_future_drop_records_cancellation_without_fabricating_a_reply() {
        let original = request();
        let signed =
            sign_direct_storage_capabilities_request(&StorageWorkKey::new(KEY).unwrap(), &original)
                .unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let notified = entered.clone();
        let app = axum::Router::new().route(
            STORAGE_CAPABILITIES_PATH,
            post(move || {
                let notified = notified.clone();
                async move {
                    notified.notify_one();
                    futures_util::future::pending::<String>().await
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let http = reqwest::Client::new();
        let mut pending = Box::pin(
            super::super::post_exchange(
                &http,
                &origin,
                STORAGE_CAPABILITIES_PATH,
                STORAGE_WORK_SIGNATURE_HEADER,
                signed,
                MAX_DIRECT_CAPABILITY_BYTES,
                &original.request_nonce,
                true,
            )
            .with_subscriber(subscriber),
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::select! {
                _ = entered.notified() => {},
                result = &mut pending => panic!("Exchange settled before cancellation: {result:?}"),
            }
        })
        .await
        .unwrap();
        drop(pending);
        server.abort();
        let rows = events.0.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["outcome"], "cancelled");
        assert_eq!(rows[1]["replyEof"], false);
        assert!(rows[1]["replyStatus"].is_null());
        assert_eq!(rows[1]["exposedReplyBytes"], "0");
    }

    #[tokio::test]
    async fn exposed_overflow_chunk_is_retained_before_the_original_bound_error() {
        let original = request();
        let signed =
            sign_direct_storage_capabilities_request(&StorageWorkKey::new(KEY).unwrap(), &original)
                .unwrap();
        let app = axum::Router::new().route(
            STORAGE_CAPABILITIES_PATH,
            post(|| async {
                (
                    [(STORAGE_WORK_SIGNATURE_HEADER, "reply-signature")],
                    "oversized",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let error = super::super::post_exchange(
            &reqwest::Client::new(),
            &origin,
            STORAGE_CAPABILITIES_PATH,
            STORAGE_WORK_SIGNATURE_HEADER,
            signed,
            4,
            &original.request_nonce,
            true,
        )
        .with_subscriber(subscriber)
        .await
        .unwrap_err();
        server.abort();

        assert_eq!(error.to_string(), "direct authority reply exceeds bound");
        let rows = events.0.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["outcome"], "reply_overflow");
        assert_eq!(rows[1]["exposedReplyBytes"], "9");
        assert_eq!(
            rows[1]["exposedReplySha256"],
            hex::encode(Sha256::digest(b"oversized"))
        );
        assert_eq!(rows[1]["replyEof"], false);
    }

    #[tokio::test]
    async fn truncated_actual_http_reply_keeps_a_nonpositive_stream_terminal() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let original = request();
        let signed =
            sign_direct_storage_capabilities_request(&StorageWorkKey::new(KEY).unwrap(), &original)
                .unwrap();
        let expected = signed.body.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut buffer = [0; 1024];
                let count = connection.read(&mut buffer).await.unwrap();
                assert!(count > 0 && request.len() + count <= MAX_DIRECT_CAPABILITY_BYTES + 8192);
                request.extend_from_slice(&buffer[..count]);
                if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            while request.len() - header_end < expected.len() {
                let mut buffer = [0; 1024];
                let count = connection.read(&mut buffer).await.unwrap();
                assert!(count > 0 && request.len() + count <= MAX_DIRECT_CAPABILITY_BYTES + 8192);
                request.extend_from_slice(&buffer[..count]);
            }
            assert_eq!(&request[header_end..], expected);
            connection.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\nx-aos-storage-work-signature: reply-signature\r\nconnection: close\r\n\r\nshort").await.unwrap();
            connection.shutdown().await.unwrap();
        });
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let error = super::super::post_exchange(
            &reqwest::Client::new(),
            &origin,
            STORAGE_CAPABILITIES_PATH,
            STORAGE_WORK_SIGNATURE_HEADER,
            signed,
            MAX_DIRECT_CAPABILITY_BYTES,
            &original.request_nonce,
            true,
        )
        .with_subscriber(subscriber)
        .await
        .unwrap_err();
        server.await.unwrap();

        assert_eq!(error.to_string(), "direct authority reply unreadable");
        let rows = events.0.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["outcome"], "stream_error");
        assert_eq!(rows[1]["replyStatus"], 200);
        assert_eq!(rows[1]["replyEof"], false);
        // A decoder may expose the available prefix before noticing truncated EOF.
        let count = rows[1]["exposedReplyBytes"]
            .as_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert!(count <= 5);
        assert_eq!(
            rows[1]["exposedReplySha256"],
            hex::encode(Sha256::digest(&b"short"[..count]))
        );
    }
}
