//! The [`MetadataHttp`] surface and its two implementations.
//!
//! Cloud fetchers need GET/PUT with custom headers, optional content-pinning,
//! and a hard per-request deadline. This module isolates that behind one
//! object-safe trait so the fetchers are testable off-box:
//!
//! - [`EngineHttp`] — production. Wraps a shared `aos_net::TransferEngine` and
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

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Result, anyhow};

use aos_net::retry::RetryConfig;
use aos_net::transfer::TransferEngine;
use aos_net::types::{HashAlgorithm, TransferRequest};

/// Default per-request deadline applied by [`EngineHttp`].
///
/// A metadata endpoint that accepts the connection but never answers must not
/// wedge boot; 5 s is generous for a link-local IMDS yet short enough that the
/// retry budget plus this deadline stays well inside the initrd time budget.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Returns `Err` on transport failure or when the per-request deadline
    /// elapses. A 404/4xx/5xx is *not* an error — it is returned as an
    /// [`HttpResponse`] with the observed status.
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse>;

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
    ) -> Result<HttpResponse>;

    /// Issue a PUT with the given body and request headers.
    ///
    /// # Errors
    ///
    /// As [`get`](MetadataHttp::get).
    async fn put(&self, url: &str, body: Vec<u8>, headers: &[(&str, &str)]) -> Result<HttpResponse>;
}

/// Production [`MetadataHttp`] over a shared `aos_net::TransferEngine`.
///
/// Every call is wrapped in `tokio::time::timeout(self.timeout, …)` — the
/// net-new shim from the build spec — because the engine's HTTP client exposes
/// only a connect timeout, not a whole-request one.
pub struct EngineHttp {
    engine: TransferEngine,
    timeout: Duration,
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
            .map_err(|_| anyhow!("metadata request to {url} timed out after {:?}", self.timeout))??;
        Ok(HttpResponse {
            status: result.status,
            body: result.body.unwrap_or_default(),
        })
    }
}

#[async_trait::async_trait]
impl MetadataHttp for EngineHttp {
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        let mut req = TransferRequest::get(url);
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
    ) -> Result<HttpResponse> {
        let mut req = TransferRequest::get(url).with_hash(HashAlgorithm::Sha256, sha256);
        for (k, v) in headers {
            req = req.with_header(k, v);
        }
        self.run(req).await
    }

    async fn put(&self, url: &str, body: Vec<u8>, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        let mut req = TransferRequest::put(url, body);
        for (k, v) in headers {
            req = req.with_header(k, v);
        }
        self.run(req).await
    }
}

/// HTTP verb used as a fixture key in [`RecordedHttp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    responses: HashMap<(RecordedMethod, String), HttpResponse>,
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

    fn lookup(&self, method: RecordedMethod, url: &str) -> Result<HttpResponse> {
        self.responses
            .get(&(method, url.to_string()))
            .cloned()
            .ok_or_else(|| anyhow!("no recorded {method:?} response for {url}"))
    }
}

#[async_trait::async_trait]
impl MetadataHttp for RecordedHttp {
    async fn get(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse> {
        self.lookup(RecordedMethod::Get, url)
    }

    async fn get_pinned(
        &self,
        url: &str,
        _sha256: &str,
        _headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        self.lookup(RecordedMethod::Get, url)
    }

    async fn put(
        &self,
        url: &str,
        _body: Vec<u8>,
        _headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        self.lookup(RecordedMethod::Put, url)
    }
}
