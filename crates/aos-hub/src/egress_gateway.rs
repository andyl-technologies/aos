//! Repository-owned hardened-egress HTTP gateway.
//!
//! Cloudflare Workers cannot bind a TLS hostname to a separately selected IP
//! address. This gateway runs the native AOS hardened client instead: DNS is
//! resolved at connect time, every answer must be globally routable, reqwest
//! receives only those exact addresses while retaining hostname SNI, proxies
//! are disabled, and redirects are followed only after the next URL passes the
//! same checks. Worker requests and gateway observations use the authenticated
//! [`aos_hub_core::egress_protocol`] contract.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};
use tokio_util::io::ReaderStream;

use aos_hub_core::db::Database;
use aos_hub_core::egress_protocol::{self, ChallengeEvidence, RequestEvidence, ResponseEvidence};

const REQUEST_CAP: usize = aos_hub_core::service::MAX_UPLOAD_BYTES;
const RESPONSE_CAP: u64 = 2 * 1024 * 1024 * 1024;
const CLOCK_SKEW_SECS: i64 = 60;
const MAX_REDIRECTS: usize = 5;

/// Shared state for the authenticated egress service.
#[derive(Clone)]
pub struct EgressGateway {
    keys: Arc<BTreeMap<String, Vec<u8>>>,
    client: reqwest::Client,
    nonce_database: Arc<Database>,
}

impl EgressGateway {
    /// Constructs a gateway with the repository's connect-time-pinned client.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no key, a key id is malformed/duplicated,
    /// or shared authentication key material is shorter than 32 bytes.
    pub async fn new(keys: Vec<(String, Vec<u8>)>, nonce_database: Arc<Database>) -> Result<Self> {
        anyhow::ensure!(
            !keys.is_empty() && keys.len() <= 2,
            "egress requires one or two overlap keys"
        );
        let mut keyring = BTreeMap::new();
        for (key_id, key) in keys {
            validate_key_id(&key_id)?;
            anyhow::ensure!(
                key.len() >= 32,
                "egress shared key must contain at least 32 bytes"
            );
            anyhow::ensure!(
                keyring.insert(key_id, key).is_none(),
                "duplicate egress key id"
            );
        }
        Ok(Self {
            keys: Arc::new(keyring),
            client: crate::fetch::hardened_client().await,
            nonce_database,
        })
    }

    /// Returns the gateway router with a hard request-body limit.
    #[must_use]
    pub fn router(self) -> axum::Router {
        axum::Router::new()
            .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
            .route("/v1/challenge", post(challenge))
            .route("/v1/fetch", post(fetch))
            .layer(DefaultBodyLimit::max(REQUEST_CAP))
            .with_state(self)
    }
}

async fn challenge(State(gateway): State<EgressGateway>, request: Request) -> Response {
    match gateway.challenge(request).await {
        Ok(response) => response,
        Err(_) => rejection(StatusCode::UNAUTHORIZED),
    }
}

async fn fetch(State(gateway): State<EgressGateway>, request: Request) -> Response {
    match gateway.fetch(request).await {
        Ok(response) => response,
        Err(_) => rejection(StatusCode::BAD_GATEWAY),
    }
}

fn rejection(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .body(Body::from("hardened egress request rejected"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

impl EgressGateway {
    async fn challenge(&self, request: Request) -> Result<Response> {
        let headers = request.headers();
        anyhow::ensure!(
            require_header(headers, "x-aos-egress-contract")? == egress_protocol::CONTRACT,
            "contract mismatch"
        );
        let key_id = require_header(headers, "x-aos-egress-key-id")?;
        let key = self.keys.get(key_id).context("unknown egress key id")?;
        let timestamp = require_header(headers, "x-aos-egress-timestamp")?
            .parse::<i64>()
            .context("invalid challenge timestamp")?;
        let nonce = require_header(headers, "x-aos-egress-nonce")?;
        let signature = require_header(headers, "x-aos-egress-signature")?;
        let evidence = ChallengeEvidence { timestamp, nonce };
        egress_protocol::verify_challenge(key, &evidence, signature)?;
        let now = aos_hub_core::clock::now_unix_secs();
        require_fresh_past_timestamp(timestamp, now).context("stale challenge")?;
        let expires_at = replay_expiry(timestamp, now)?;
        let digest = egress_protocol::body_sha256(signature.as_bytes());
        anyhow::ensure!(
            self.nonce_database
                .admit_egress_request(nonce, &digest, now, expires_at)
                .await?,
            "replayed challenge"
        );
        let response_timestamp = aos_hub_core::clock::now_unix_secs();
        let response_evidence = ChallengeEvidence {
            timestamp: response_timestamp,
            nonce,
        };
        let response_signature = egress_protocol::sign_challenge_response(key, &response_evidence)?;
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("cache-control", "no-store")
            .header("x-aos-egress-contract", egress_protocol::CONTRACT)
            .header("x-aos-egress-key-id", key_id)
            .header("x-aos-egress-timestamp", response_timestamp.to_string())
            .header("x-aos-egress-nonce", nonce)
            .header("x-aos-egress-signature", response_signature)
            .body(Body::empty())
            .context("building challenge response")
    }

    async fn fetch(&self, request: Request) -> Result<Response> {
        let (parts, request_body) = request.into_parts();
        let headers = parts.headers;
        require_header(&headers, "x-aos-egress-contract").and_then(|contract| {
            anyhow::ensure!(contract == egress_protocol::CONTRACT, "contract mismatch");
            Ok(contract)
        })?;
        let key_id = require_header(&headers, "x-aos-egress-key-id")?;
        let key = self.keys.get(key_id).context("unknown egress key id")?;
        let timestamp = require_header(&headers, "x-aos-egress-timestamp")?
            .parse::<i64>()
            .context("invalid request timestamp")?;
        let nonce = require_header(&headers, "x-aos-egress-nonce")?;
        let target_url = require_header(&headers, "x-aos-egress-target-url")?;
        let method = require_header(&headers, "x-aos-egress-upstream-method")?;
        let body_digest = require_header(&headers, "x-aos-egress-body-sha256")?;
        let signature = require_header(&headers, "x-aos-egress-signature")?;
        let content_type = optional_header(&headers, "x-aos-egress-upstream-content-type")?;
        let range = optional_header(&headers, "x-aos-egress-upstream-range")?;
        let if_match = optional_header(&headers, "x-aos-egress-upstream-if-match")?;
        let authorization = optional_header(&headers, "x-aos-egress-upstream-authorization")?;
        let webhook_event = optional_header(&headers, "x-aos-egress-upstream-webhook-event")?;
        let webhook_signature =
            optional_header(&headers, "x-aos-egress-upstream-webhook-signature")?;
        let webhook_delivery_id =
            optional_header(&headers, "x-aos-egress-upstream-webhook-delivery-id")?;
        let evidence = RequestEvidence {
            timestamp,
            nonce,
            target_url,
            method,
            body_sha256: body_digest,
            content_type,
            range,
            if_match,
            authorization,
            webhook_event,
            webhook_signature,
            webhook_delivery_id,
        };
        egress_protocol::verify_request(key, &evidence, signature)?;
        let now = aos_hub_core::clock::now_unix_secs();
        require_fresh_past_timestamp(timestamp, now).context("stale request")?;
        let expires_at = replay_expiry(timestamp, now)?;
        let request_digest = egress_protocol::request_digest(&evidence)?;

        // Authenticate the complete request body before replay admission and
        // before opening any upstream connection. Spooling to an anonymous
        // file keeps memory bounded while preserving streaming/backpressure on
        // the later upstream send.
        let mut spool = tokio::fs::File::from_std(
            tempfile::tempfile().context("creating egress request spool")?,
        );
        let mut hasher = Sha256::new();
        let mut received = 0_usize;
        let mut incoming = request_body.into_data_stream();
        while let Some(chunk) = incoming.next().await {
            let chunk = chunk.context("reading gateway request stream")?;
            received = received
                .checked_add(chunk.len())
                .context("gateway request length overflow")?;
            anyhow::ensure!(received <= REQUEST_CAP, "gateway request cap exceeded");
            hasher.update(&chunk);
            spool
                .write_all(&chunk)
                .await
                .context("writing egress request spool")?;
        }
        anyhow::ensure!(
            hex::encode(hasher.finalize()) == body_digest,
            "body digest mismatch"
        );
        spool
            .flush()
            .await
            .context("flushing egress request spool")?;
        spool
            .rewind()
            .await
            .context("rewinding egress request spool")?;
        anyhow::ensure!(
            self.nonce_database
                .admit_egress_request(nonce, &request_digest, now, expires_at,)
                .await?,
            "replayed request"
        );

        let method = reqwest::Method::from_bytes(method.as_bytes()).context("invalid method")?;
        let mut request_body = Some(reqwest::Body::wrap_stream(ReaderStream::new(spool)));
        let mut current = url::Url::parse(target_url).context("invalid target URL")?;
        let mut redirects = 0;
        let response = loop {
            aos_hub_core::url_guard::is_safe_remote_url(current.as_str())?;
            anyhow::ensure!(
                current.username().is_empty()
                    && current.password().is_none()
                    && current.fragment().is_none(),
                "upstream URL cannot contain credentials or a fragment"
            );
            let mut request = self.client.request(method.clone(), current.clone());
            if let Some(value) = content_type {
                request = request.header(reqwest::header::CONTENT_TYPE, value);
            }
            if let Some(value) = range {
                request = request.header(reqwest::header::RANGE, value);
            }
            if let Some(value) = if_match {
                request = request.header(reqwest::header::IF_MATCH, value);
            }
            if let Some(value) = authorization {
                request = request.header(reqwest::header::AUTHORIZATION, value);
            }
            if let Some(value) = webhook_event {
                request = request.header("X-AOS-Event", value);
            }
            if let Some(value) = webhook_signature {
                request = request.header("X-AOS-Signature", value);
            }
            if let Some(value) = webhook_delivery_id {
                request = request.header("X-AOS-Delivery-ID", value);
            }
            if let Some(body) = request_body.take() {
                request = request.body(body);
            }
            let response = request.send().await.context("upstream transport failed")?;
            if !response.status().is_redirection() {
                break response;
            }
            anyhow::ensure!(
                matches!(method, reqwest::Method::GET | reqwest::Method::HEAD),
                "redirect refused for mutating method"
            );
            anyhow::ensure!(
                body_digest == egress_protocol::body_sha256(&[]),
                "redirect refused for a request with a body"
            );
            anyhow::ensure!(redirects < MAX_REDIRECTS, "redirect limit exceeded");
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .context("redirect omitted Location")?
                .to_str()
                .context("redirect Location is not text")?;
            let next = current
                .join(location)
                .context("invalid redirect Location")?;
            if authorization.is_some() {
                anyhow::ensure!(
                    current.scheme() == next.scheme()
                        && current.host_str() == next.host_str()
                        && current.port_or_known_default() == next.port_or_known_default(),
                    "authenticated redirect changed origin"
                );
            }
            current = next;
            redirects += 1;
        };

        let peer = response
            .remote_addr()
            .context("upstream peer address is unavailable")?;
        validate_peer(peer)?;
        let final_url = response.url().to_string();
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > RESPONSE_CAP)
        {
            anyhow::bail!("upstream response exceeds the gateway cap");
        }
        let response_timestamp = aos_hub_core::clock::now_unix_secs();
        let response_signature = egress_protocol::sign_response(
            key,
            &ResponseEvidence {
                timestamp: response_timestamp,
                nonce,
                final_url: &final_url,
                peer_ip: &peer.ip().to_string(),
                status: status.as_u16(),
            },
        )?;

        let mut builder = Response::builder().status(status);
        for name in [
            reqwest::header::CONTENT_TYPE,
            reqwest::header::CONTENT_LENGTH,
            reqwest::header::CONTENT_RANGE,
            reqwest::header::ETAG,
            reqwest::header::LAST_MODIFIED,
        ] {
            if let Some(value) = response.headers().get(&name) {
                builder = builder.header(name, value);
            }
        }
        builder = builder
            .header("cache-control", "no-store")
            .header("x-aos-egress-contract", egress_protocol::CONTRACT)
            .header("x-aos-egress-key-id", key_id)
            .header("x-aos-egress-timestamp", response_timestamp.to_string())
            .header("x-aos-egress-nonce", nonce)
            .header("x-aos-egress-final-url", final_url)
            .header("x-aos-egress-peer-ip", peer.ip().to_string())
            .header("x-aos-egress-upstream-status", status.as_u16().to_string())
            .header("x-aos-egress-signature", response_signature);

        let stream = response.bytes_stream().scan((0_u64, false), |state, item| {
            let output = if state.1 {
                None
            } else {
                match item {
                    Ok(bytes) if state.0 + bytes.len() as u64 <= RESPONSE_CAP => {
                        state.0 += bytes.len() as u64;
                        Some(Ok(bytes))
                    }
                    Ok(_) => {
                        state.1 = true;
                        Some(Err(std::io::Error::other("egress response cap exceeded")))
                    }
                    Err(_) => {
                        state.1 = true;
                        Some(Err(std::io::Error::other("egress upstream stream failed")))
                    }
                }
            };
            std::future::ready(output)
        });
        builder
            .body(Body::from_stream(stream))
            .context("building gateway response")
    }
}

fn validate_key_id(key_id: &str) -> Result<()> {
    anyhow::ensure!(
        !key_id.is_empty()
            && key_id.len() <= 64
            && key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "invalid egress key id"
    );
    Ok(())
}

fn replay_expiry(timestamp: i64, now: i64) -> Result<i64> {
    let expires_at = timestamp
        .checked_add(CLOCK_SKEW_SECS)
        .context("egress replay-window timestamp overflow")?;
    anyhow::ensure!(
        expires_at > now,
        "egress evidence has no remaining replay window"
    );
    Ok(expires_at)
}

fn require_fresh_past_timestamp(timestamp: i64, now: i64) -> Result<()> {
    let age = now
        .checked_sub(timestamp)
        .context("egress timestamp is in the future")?;
    anyhow::ensure!(age >= 0, "egress timestamp is in the future");
    anyhow::ensure!(age <= CLOCK_SKEW_SECS, "egress timestamp is stale");
    Ok(())
}

fn validate_peer(peer: SocketAddr) -> Result<()> {
    let ip: IpAddr = peer.ip();
    anyhow::ensure!(
        aos_hub_core::url_guard::is_global_ip(ip),
        "upstream peer is non-global"
    );
    Ok(())
}

fn require_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str> {
    headers
        .get(HeaderName::from_static(name))
        .context("required egress header is absent")?
        .to_str()
        .context("egress header is not text")
}

fn optional_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<Option<&'a str>> {
    headers
        .get(HeaderName::from_static(name))
        .map(HeaderValue::to_str)
        .transpose()
        .context("egress header is not text")
}

#[cfg(test)]
mod tests {
    use tower::ServiceExt as _;

    use super::*;

    #[test]
    fn rejects_non_global_peers() {
        assert!(validate_peer("127.0.0.1:443".parse().unwrap()).is_err());
        assert!(validate_peer("10.0.0.1:443".parse().unwrap()).is_err());
        assert!(validate_peer("1.1.1.1:443".parse().unwrap()).is_ok());
    }

    #[test]
    fn replay_expiry_is_bounded_by_signed_timestamp() {
        assert_eq!(replay_expiry(1_000, 1_001).unwrap(), 1_060);
        assert!(replay_expiry(1_000, 1_060).is_err());
        assert!(replay_expiry(i64::MAX, 1_000).is_err());
    }

    #[test]
    fn freshness_rejects_future_and_old_evidence() {
        assert!(require_fresh_past_timestamp(1_000, 1_000).is_ok());
        assert!(require_fresh_past_timestamp(1_000, 1_060).is_ok());
        assert!(require_fresh_past_timestamp(1_001, 1_000).is_err());
        assert!(require_fresh_past_timestamp(1_000, 1_061).is_err());
    }

    fn challenge_request(key_id: &str, key: &[u8], timestamp: i64, nonce: &str) -> Request {
        let evidence = ChallengeEvidence { timestamp, nonce };
        let signature = egress_protocol::sign_challenge(key, &evidence).unwrap();
        Request::builder()
            .method("POST")
            .uri("/v1/challenge")
            .header("x-aos-egress-contract", egress_protocol::CONTRACT)
            .header("x-aos-egress-key-id", key_id)
            .header("x-aos-egress-timestamp", timestamp.to_string())
            .header("x-aos-egress-nonce", nonce)
            .header("x-aos-egress-signature", signature)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn challenge_rejects_wrong_key_and_stale_evidence_before_fetch() {
        let key = vec![7_u8; 32];
        let database = Arc::new(Database::open_in_memory().await.unwrap());
        let router = EgressGateway::new(
            vec![
                ("current".to_string(), key.clone()),
                ("next".to_string(), vec![9_u8; 32]),
            ],
            database,
        )
        .await
        .unwrap()
        .router();
        let now = aos_hub_core::clock::now_unix_secs();
        let nonce = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let wrong = router
            .clone()
            .oneshot(challenge_request("current", &[8_u8; 32], now, nonce))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let stale = router
            .clone()
            .oneshot(challenge_request(
                "current",
                &key,
                now - CLOCK_SKEW_SECS - 1,
                nonce,
            ))
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

        let future = router
            .clone()
            .oneshot(challenge_request("current", &key, now + 1, nonce))
            .await
            .unwrap();
        assert_eq!(future.status(), StatusCode::UNAUTHORIZED);

        let unknown = router
            .clone()
            .oneshot(challenge_request("retired", &key, now, nonce))
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);

        let fresh = router
            .oneshot(challenge_request("next", &[9_u8; 32], now, nonce))
            .await
            .unwrap();
        assert_eq!(fresh.status(), StatusCode::NO_CONTENT);
        assert_eq!(fresh.headers().get("x-aos-egress-nonce").unwrap(), nonce);
    }

    #[tokio::test]
    async fn body_digest_is_verified_before_admission_or_upstream_io() {
        let key = vec![7_u8; 32];
        let database = Arc::new(Database::open_in_memory().await.unwrap());
        let router = EgressGateway::new(
            vec![("current".to_string(), key.clone())],
            Arc::clone(&database),
        )
        .await
        .unwrap()
        .router();
        let now = aos_hub_core::clock::now_unix_secs();
        let nonce = "bodydigestabcdefghijklmnopqrstuvwxyz0123456789";
        let expected_digest = egress_protocol::body_sha256(b"expected");
        let evidence = RequestEvidence {
            timestamp: now,
            nonce,
            target_url: "https://example.com/object",
            method: "PUT",
            body_sha256: &expected_digest,
            content_type: None,
            range: None,
            if_match: None,
            authorization: None,
            webhook_event: None,
            webhook_signature: None,
            webhook_delivery_id: None,
        };
        let request_digest = egress_protocol::request_digest(&evidence).unwrap();
        let signature = egress_protocol::sign_request(&key, &evidence).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/fetch")
            .header("x-aos-egress-contract", egress_protocol::CONTRACT)
            .header("x-aos-egress-key-id", "current")
            .header("x-aos-egress-timestamp", now.to_string())
            .header("x-aos-egress-nonce", nonce)
            .header("x-aos-egress-target-url", evidence.target_url)
            .header("x-aos-egress-upstream-method", evidence.method)
            .header("x-aos-egress-body-sha256", &expected_digest)
            .header("x-aos-egress-signature", signature)
            .body(Body::from("different"))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(database
            .admit_egress_request(nonce, &request_digest, now, now + CLOCK_SKEW_SECS)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn webhook_header_tampering_is_rejected_before_upstream_io() {
        let key = vec![11_u8; 32];
        let database = Arc::new(Database::open_in_memory().await.unwrap());
        let router = EgressGateway::new(
            vec![("current".to_string(), key.clone())],
            Arc::clone(&database),
        )
        .await
        .unwrap()
        .router();
        let now = aos_hub_core::clock::now_unix_secs();
        let nonce = "webhooktamperabcdefghijklmnopqrstuvwxyz0123456789";
        let body = br#"{"event":"release.published"}"#;
        let digest = egress_protocol::body_sha256(body);
        let webhook_signature =
            "sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let evidence = RequestEvidence {
            timestamp: now,
            nonce,
            target_url: "https://example.com/hook",
            method: "POST",
            body_sha256: &digest,
            content_type: Some("application/json"),
            range: None,
            if_match: None,
            authorization: None,
            webhook_event: Some("release.published"),
            webhook_signature: Some(webhook_signature),
            webhook_delivery_id: Some("delivery_01HZX"),
        };
        let signature = egress_protocol::sign_request(&key, &evidence).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/fetch")
            .header("x-aos-egress-contract", egress_protocol::CONTRACT)
            .header("x-aos-egress-key-id", "current")
            .header("x-aos-egress-timestamp", now.to_string())
            .header("x-aos-egress-nonce", nonce)
            .header("x-aos-egress-target-url", evidence.target_url)
            .header("x-aos-egress-upstream-method", evidence.method)
            .header("x-aos-egress-body-sha256", &digest)
            .header("x-aos-egress-upstream-content-type", "application/json")
            .header("x-aos-egress-upstream-webhook-event", "release.deleted")
            .header("x-aos-egress-upstream-webhook-signature", webhook_signature)
            .header(
                "x-aos-egress-upstream-webhook-delivery-id",
                "delivery_01HZX",
            )
            .header("x-aos-egress-signature", signature)
            .body(Body::from(body.as_slice()))
            .unwrap();
        assert_eq!(
            router.oneshot(request).await.unwrap().status(),
            StatusCode::BAD_GATEWAY
        );
    }
}
