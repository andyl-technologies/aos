//! The [`MetadataHttp`] surface and its two implementations.
//!
//! Cloud fetchers need GET/PUT with custom headers, optional content-pinning,
//! and a hard per-request deadline. This module isolates that behind one
//! object-safe trait so the fetchers are testable off-box:
//!
//! - [`EngineHttp`] — production. Wraps a shared `aos_transfer::TransferEngine` and
//!   `RetryConfig`, and the net-new `tokio::time::timeout` shim around every
//!   `engine.execute(...)`. The engine's client is a process-wide singleton
//!   with only a connect timeout, so a black-hole metadata endpoint could
//!   otherwise wedge boot; the shim bounds each call.
//! - [`RecordedHttp`] — test double. Answers from a fixture map keyed by
//!   `(method, url)`, so the AWS IMDSv2 token dance and every cloud GET are
//!   replayable with no network.
//!
//! A 404 is *not* an error here: it is surfaced as [`HttpResponse`] with
//! `status == 404` so a fetcher can map "no user-data attached" to `Ok(None)`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow};

use aos_transfer::retry::RetryConfig;
use aos_transfer::transfer::TransferEngine;
use aos_transfer::types::{HashAlgorithm, TransferRequest};

/// Default per-request deadline applied by [`EngineHttp`].
///
/// A metadata endpoint that accepts the connection but never answers must not
/// wedge boot; 5 s is generous for a link-local IMDS yet short enough that the
/// retry budget plus this deadline stays well inside the initrd time budget.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum bytes accepted across one metadata acquisition transaction.
pub const MAX_ACQUISITION_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum exact operator configuration bytes.
pub const MAX_USER_DATA_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum encoded Azure user-data bytes before base64 decoding.
pub const MAX_ENCODED_USER_DATA_BYTES: u64 = 24 * 1024 * 1024;
/// Maximum bytes accepted for one platform facts document.
pub const MAX_FACT_DOCUMENT_BYTES: u64 = 1024 * 1024;
/// Maximum detached-signature bytes.
pub const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
/// Maximum metadata session-token bytes.
pub const MAX_TOKEN_BYTES: u64 = 8 * 1024;

/// A buffered HTTP-like response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code (or protocol equivalent).
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Return the body iff the status is a 2xx success, consuming `self`.
    ///
    /// A non-2xx response (notably 404 "no user-data") yields `None` so the
    /// caller can branch without inspecting the status directly.
    pub fn into_ok_body(self) -> Option<Vec<u8>> {
        if (200..300).contains(&self.status) {
            Some(self.body)
        } else {
            None
        }
    }

    /// The body decoded as UTF-8, iff the status is 2xx and the bytes are
    /// valid UTF-8.
    pub fn into_ok_string(self) -> Option<String> {
        self.into_ok_body().and_then(|b| String::from_utf8(b).ok())
    }
}

/// GET/PUT with custom headers and optional content-pinning, with a hard
/// per-request deadline.
///
/// Object-safe so the dispatcher can hand `&dyn MetadataHttp` to a
/// `Box<dyn PlatformFetcher>` without knowing which implementation backs it.
#[async_trait::async_trait]
pub trait MetadataHttp: Send + Sync {
    /// Issue a GET with the given request headers.
    ///
    /// # Errors
    ///
    /// Returns `Err` on transport failure, a per-request or aggregate size
    /// limit, or when the per-request deadline elapses. A 404/4xx/5xx is *not*
    /// an error — it is returned as an [`HttpResponse`] with the observed
    /// status.
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse>;

    /// Issue a content-pinned GET: the transfer must hash to `sha256` (lowercase
    /// hex, optionally `sha256:`-prefixed) or it fails.
    ///
    /// # Errors
    ///
    /// As [`get`](MetadataHttp::get), plus a hash-mismatch error when the body
    /// does not match the pin.
    async fn get_pinned(
        &self,
        url: &str,
        sha256: &str,
        headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse>;

    /// Issue a PUT with the given body and request headers.
    ///
    /// # Errors
    ///
    /// As [`get`](MetadataHttp::get).
    async fn put(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse>;
}

/// Production [`MetadataHttp`] over a shared `aos_transfer::TransferEngine`.
///
/// Every call is wrapped in `tokio::time::timeout(self.timeout, …)` — the
/// net-new shim from the build spec — because the engine's HTTP client exposes
/// only a connect timeout, not a whole-request one.
pub struct EngineHttp {
    engine: TransferEngine,
    timeout: Duration,
    received_bytes: AtomicU64,
}

impl EngineHttp {
    /// Build an adapter over `engine` using the given retry policy and the
    /// default per-request timeout.
    ///
    /// The retry policy is threaded into the engine config by the caller; it
    /// is accepted here for API symmetry with the build-spec reuse map and to
    /// document that retries live below this shim.
    pub fn new(engine: TransferEngine) -> Self {
        Self {
            engine,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            received_bytes: AtomicU64::new(0),
        }
    }

    /// Override the per-request deadline (mainly for tests).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The default retry policy the metadata agent uses (3 attempts, jitter).
    ///
    /// Exposed so the caller can build a `TransferEngine` with a matching
    /// policy before handing it to [`EngineHttp::new`].
    pub fn default_retry() -> RetryConfig {
        RetryConfig::default()
    }

    async fn run(&self, request: TransferRequest) -> Result<HttpResponse> {
        let url = request.url.clone();
        let fut = self.engine.execute(request);
        let result = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| {
                anyhow!(
                    "metadata request to {url} timed out after {:?}",
                    self.timeout
                )
            })??;
        let response = HttpResponse {
            status: result.status,
            body: result.body.unwrap_or_default(),
        };
        charge_budget(&self.received_bytes, response.body.len() as u64)?;
        Ok(response)
    }
}

#[async_trait::async_trait]
impl MetadataHttp for EngineHttp {
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse> {
        let mut req = TransferRequest::get(url).with_maximum_bytes(maximum_bytes);
        for (k, v) in headers {
            req = req.with_header(k, v);
        }
        self.run(req).await
    }

    async fn get_pinned(
        &self,
        url: &str,
        sha256: &str,
        headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse> {
        let mut req = TransferRequest::get(url)
            .with_hash(HashAlgorithm::Sha256, sha256)
            .with_maximum_bytes(maximum_bytes);
        for (k, v) in headers {
            req = req.with_header(k, v);
        }
        self.run(req).await
    }

    async fn put(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse> {
        let mut req = TransferRequest::put(url, body).with_maximum_bytes(maximum_bytes);
        for (k, v) in headers {
            req = req.with_header(k, v);
        }
        self.run(req).await
    }
}

/// HTTP verb used as a fixture key in [`RecordedHttp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordedMethod {
    /// A recorded GET (covers both plain and content-pinned).
    Get,
    /// A recorded PUT (the IMDSv2 token request).
    Put,
}

/// A [`MetadataHttp`] that replays recorded fixtures, for off-box unit tests.
///
/// Insert responses with [`on`](RecordedHttp::on); unmatched requests return an
/// error so a test fails loudly rather than silently hitting the network
/// (which it cannot, anyway).
#[derive(Default)]
pub struct RecordedHttp {
    responses: BTreeMap<(RecordedMethod, String), HttpResponse>,
    received_bytes: AtomicU64,
}

impl RecordedHttp {
    /// Create an empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a response for `(method, url)`.
    pub fn on(mut self, method: RecordedMethod, url: &str, status: u16, body: &[u8]) -> Self {
        self.responses.insert(
            (method, url.to_string()),
            HttpResponse {
                status,
                body: body.to_vec(),
            },
        );
        self
    }

    fn lookup(
        &self,
        method: RecordedMethod,
        url: &str,
        maximum_bytes: u64,
    ) -> Result<HttpResponse> {
        let response = self
            .responses
            .get(&(method, url.to_string()))
            .cloned()
            .ok_or_else(|| anyhow!("no recorded {method:?} response for {url}"))?;
        anyhow::ensure!(
            response.body.len() as u64 <= maximum_bytes,
            "metadata response exceeds {maximum_bytes} byte limit"
        );
        charge_budget(&self.received_bytes, response.body.len() as u64)?;
        Ok(response)
    }
}

#[async_trait::async_trait]
impl MetadataHttp for RecordedHttp {
    async fn get(
        &self,
        url: &str,
        _headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse> {
        self.lookup(RecordedMethod::Get, url, maximum_bytes)
    }

    async fn get_pinned(
        &self,
        url: &str,
        _sha256: &str,
        _headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse> {
        self.lookup(RecordedMethod::Get, url, maximum_bytes)
    }

    async fn put(
        &self,
        url: &str,
        _body: Vec<u8>,
        _headers: &[(&str, &str)],
        maximum_bytes: u64,
    ) -> Result<HttpResponse> {
        self.lookup(RecordedMethod::Put, url, maximum_bytes)
    }
}

fn charge_budget(received: &AtomicU64, bytes: u64) -> Result<()> {
    received
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current
                .checked_add(bytes)
                .filter(|next| *next <= MAX_ACQUISITION_BYTES)
        })
        .map_err(|_| anyhow!("metadata acquisition exceeds aggregate byte limit"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquisition_budget_accepts_exact_limit_and_rejects_more() {
        let received = AtomicU64::new(0);

        charge_budget(&received, MAX_ACQUISITION_BYTES).unwrap();

        assert!(charge_budget(&received, 1).is_err());
    }
}
