//! Transfer engine -- the main public API.
//!
//! Orchestrates downloads/uploads using the connection pool, protocol layer,
//! retry logic, hash verification, progress tracking, and bandwidth limiting.
//! All transfers use a streaming/chunked architecture: hash verification,
//! bandwidth limiting, and progress tracking happen per-chunk during the
//! transfer rather than after it completes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::auth::AuthStore;
use crate::bandwidth::BandwidthLimiter;
use crate::hash::StreamingHasher;
use crate::pool::{ConnectionPool, PoolConfig};
use crate::progress::{BatchProgressHandler, NoopProgress, ProgressHandler};
use crate::protocol;
use crate::retry::{self, ErrorClass, RetryConfig, classify_error};
use crate::types::{Method, TransferOutput, TransferRequest, TransferResult};

/// Configuration for the transfer engine.
#[derive(Debug, Clone)]
pub struct TransferEngineConfig {
    /// Connection pool configuration.
    pub pool: PoolConfig,
    /// Retry configuration.
    pub retry: RetryConfig,
    /// Maximum bandwidth in bytes/sec. `None` means unlimited.
    pub max_bandwidth: Option<u64>,
    /// Minimum speed in bytes/sec. Abort transfer if below this for too long.
    /// `None` disables the check.
    pub min_speed: Option<u64>,
    /// Grace period before `min_speed` is enforced. The average speed
    /// since the start of the transfer is checked only after this much
    /// time has elapsed.
    pub min_speed_duration: Duration,
}

impl Default for TransferEngineConfig {
    fn default() -> Self {
        Self {
            pool: PoolConfig::default(),
            retry: RetryConfig::default(),
            max_bandwidth: None,
            min_speed: None,
            min_speed_duration: Duration::from_secs(30),
        }
    }
}

/// The transfer engine -- primary interface for all network operations.
///
/// Manages connection pooling, retry logic, hash verification, progress
/// reporting, and bandwidth limiting. All transfers use streaming I/O:
/// hash, bandwidth, and progress are applied per-chunk.
pub struct TransferEngine {
    pool: ConnectionPool,
    auth: AuthStore,
    bandwidth: Option<BandwidthLimiter>,
    retry: RetryConfig,
    min_speed: Option<u64>,
    min_speed_duration: Duration,
    progress: Box<dyn ProgressHandler>,
}

impl TransferEngine {
    /// Create a new transfer engine with the given configuration.
    ///
    /// The engine starts with an empty [`AuthStore`] (add credentials
    /// via [`auth`](TransferEngine::auth)) and a no-op progress
    /// handler (replace it with
    /// [`set_progress`](TransferEngine::set_progress)).
    pub fn new(config: TransferEngineConfig) -> Self {
        let bandwidth = config.max_bandwidth.map(BandwidthLimiter::new);

        Self {
            pool: ConnectionPool::new(config.pool),
            auth: AuthStore::new(),
            bandwidth,
            retry: config.retry,
            min_speed: config.min_speed,
            min_speed_duration: config.min_speed_duration,
            progress: Box::new(NoopProgress),
        }
    }

    /// Set the progress handler for single transfers.
    pub fn set_progress(&mut self, handler: Box<dyn ProgressHandler>) {
        self.progress = handler;
    }

    /// Get a reference to the auth store for adding credentials.
    pub fn auth(&self) -> &AuthStore {
        &self.auth
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &ConnectionPool {
        &self.pool
    }

    /// Execute a single transfer with streaming hash, bandwidth, progress, and retry.
    ///
    /// GET requests use the streaming path: the response body is
    /// processed chunk-by-chunk, with hash updates, bandwidth-limiter
    /// consumption, progress callbacks, and minimum-speed enforcement
    /// applied per chunk as it is written to the request's output.
    /// Other methods go through the protocol's buffered `execute`
    /// path, with hashing and bandwidth applied afterwards.
    ///
    /// Transient failures are retried per the engine's [`RetryConfig`]
    /// with exponential backoff. A 401 response additionally triggers
    /// one token-refresh attempt (see [`AuthStore::refresh_token`])
    /// before retrying.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - the URL scheme is unsupported,
    /// - the transfer fails with a permanent error (e.g. HTTP 4xx), or
    ///   keeps failing transiently until retries are exhausted,
    /// - the computed hash does not match the request's [`HashSpec`](crate::types::HashSpec),
    /// - the response body exceeds [`TransferRequest::maximum_bytes`],
    /// - the average speed stays below the configured minimum after
    ///   the grace period, or
    /// - writing to the output destination fails.
    #[allow(clippy::disallowed_methods)]
    pub async fn execute(&self, request: TransferRequest) -> Result<TransferResult> {
        let url = request.url.clone();
        let hash_spec = request.hash.clone();
        let host = extract_host(&url).unwrap_or_else(|| "unknown".to_string());
        let proto = protocol::for_url(&url)?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut token_refreshed = false;

        for attempt in 0..self.retry.max_attempts {
            if attempt > 0 {
                let delay = retry::compute_retry_delay(&self.retry, attempt - 1);
                tracing::debug!(attempt, delay_ms = delay.as_millis(), "retrying");
                tokio::time::sleep(delay).await;
            }

            let _permit = self.pool.acquire(&host).await;
            let credential = self.auth.get(&url);

            // Use the streaming path for GET requests, legacy path for others.
            let stream_result = if request.method == Method::Get {
                proto.stream(&request, credential.as_ref()).await
            } else {
                // Non-GET: use execute directly (PUT/HEAD/DELETE don't stream response).
                match proto.execute(&request, credential.as_ref()).await {
                    Ok(result) => {
                        // Apply bandwidth limiting for the bytes transferred.
                        if let Some(ref limiter) = self.bandwidth {
                            limiter.consume(result.bytes_transferred).await;
                        }

                        // Hash verification on body if available.
                        if let (Some(ref spec), Some(ref body)) = (&hash_spec, &result.body) {
                            let mut hasher =
                                StreamingHasher::with_expected(spec.algorithm, &spec.expected);
                            hasher.update(body);
                            let hash_result = hasher.finalize();

                            if let Some(false) = hash_result.matched {
                                let err = anyhow::anyhow!(
                                    "hash mismatch for {}: expected {}, got {}",
                                    url,
                                    spec.expected,
                                    hash_result.hex
                                );
                                self.progress.on_error(&url, &err);
                                return Err(err);
                            }
                        }

                        self.progress.on_progress(
                            &url,
                            result.bytes_transferred,
                            result.content_length,
                        );
                        self.progress.on_complete(&url, result.bytes_transferred);
                        return Ok(result);
                    }
                    Err(e) => Err(e),
                }
            };

            match stream_result {
                Ok((mut result, mut stream)) => {
                    if let (Some(maximum), Some(content_length)) =
                        (request.maximum_bytes, result.content_length)
                    {
                        let projected = result
                            .bytes_transferred
                            .checked_add(content_length)
                            .ok_or_else(|| {
                                anyhow::anyhow!("transfer byte count overflow for {url}")
                            })?;
                        if projected > maximum {
                            let err = anyhow::anyhow!(
                                "response from {url} exceeds the {maximum} byte limit"
                            );
                            self.progress.on_error(&url, &err);
                            return Err(err);
                        }
                    }

                    // Set up the streaming pipeline.
                    let mut hasher = hash_spec
                        .as_ref()
                        .map(|h| StreamingHasher::with_expected(h.algorithm, &h.expected));
                    let mut bytes_transferred: u64 = result.bytes_transferred;
                    let transfer_start = Instant::now();

                    self.progress.on_start(&url, result.content_length);

                    // Open output destination.
                    let mut file_sink: Option<tokio::fs::File> = None;
                    let mut memory_sink: Option<Vec<u8>> = None;

                    match &request.output {
                        TransferOutput::File(path) => {
                            if let Some(parent) = path.parent() {
                                tokio::fs::create_dir_all(parent).await?;
                            }
                            let file = if result.resumed {
                                tokio::fs::OpenOptions::new()
                                    .append(true)
                                    .open(path)
                                    .await?
                            } else {
                                tokio::fs::File::create(path).await?
                            };
                            file_sink = Some(file);
                        }
                        TransferOutput::Memory => {
                            memory_sink = Some(Vec::new());
                        }
                        TransferOutput::Callback(_) => {
                            // Callback is handled inline below.
                        }
                    }

                    // Stream chunks with per-chunk hash/bandwidth/progress.
                    while let Some(chunk_result) = stream.next().await {
                        let chunk = chunk_result?;
                        let next_bytes = bytes_transferred
                            .checked_add(chunk.len() as u64)
                            .ok_or_else(|| {
                                anyhow::anyhow!("transfer byte count overflow for {url}")
                            })?;
                        if let Some(maximum) = request.maximum_bytes {
                            if next_bytes > maximum {
                                let err = anyhow::anyhow!(
                                    "response from {url} exceeds the {maximum} byte limit"
                                );
                                self.progress.on_error(&url, &err);
                                return Err(err);
                            }
                        }

                        // Hash update.
                        if let Some(ref mut h) = hasher {
                            h.update(&chunk);
                        }

                        // Bandwidth limiting (may block).
                        if let Some(ref limiter) = self.bandwidth {
                            limiter.consume(chunk.len() as u64).await;
                        }

                        // Write to output.
                        if let Some(ref mut f) = file_sink {
                            f.write_all(&chunk).await?;
                        } else if let Some(ref mut buf) = memory_sink {
                            buf.extend_from_slice(&chunk);
                        } else if let TransferOutput::Callback(ref cb) = request.output {
                            cb(&chunk)?;
                        }

                        // Track progress.
                        bytes_transferred = next_bytes;
                        self.progress
                            .on_progress(&url, bytes_transferred, result.content_length);

                        // Min speed enforcement.
                        if let Some(min_speed) = self.min_speed {
                            let elapsed = transfer_start.elapsed();
                            if elapsed > self.min_speed_duration {
                                let speed = bytes_transferred as f64 / elapsed.as_secs_f64();
                                if speed < min_speed as f64 {
                                    let err = anyhow::anyhow!(
                                        "transfer speed {:.0} B/s below minimum {} B/s for {}",
                                        speed,
                                        min_speed,
                                        url
                                    );
                                    self.progress.on_error(&url, &err);
                                    return Err(err);
                                }
                            }
                        }
                    }

                    // Flush file output.
                    if let Some(ref mut f) = file_sink {
                        f.flush().await?;
                    }

                    // Finalize hash.
                    if let Some(hasher) = hasher {
                        let hash_result = hasher.finalize();
                        result.hash = Some(hash_result.hex.clone());

                        if let Some(false) = hash_result.matched {
                            let err = anyhow::anyhow!(
                                "hash mismatch for {}: expected {}, got {}",
                                url,
                                hash_spec
                                    .as_ref()
                                    .map(|h| h.expected.as_str())
                                    .unwrap_or("?"),
                                hash_result.hex
                            );
                            self.progress.on_error(&url, &err);
                            return Err(err);
                        }
                    }

                    result.bytes_transferred = bytes_transferred;
                    result.body = memory_sink;

                    self.progress.on_complete(&url, bytes_transferred);
                    return Ok(result);
                }
                Err(err) => {
                    // Check for 401 and attempt token refresh.
                    if !token_refreshed {
                        let err_msg = format!("{err}");
                        let is_401 = err
                            .downcast_ref::<reqwest::Error>()
                            .and_then(|e| e.status())
                            .map(|s| s == reqwest::StatusCode::UNAUTHORIZED)
                            .unwrap_or(false)
                            || err_msg.contains("HTTP 401");

                        if is_401 {
                            if let Some(ref host_str) = extract_host(&url) {
                                let http_client = reqwest::Client::new();
                                if self
                                    .auth
                                    .refresh_token(host_str, &http_client)
                                    .await
                                    .unwrap_or(false)
                                {
                                    tracing::info!("refreshed auth token for {host_str}, retrying");
                                    token_refreshed = true;
                                    last_err = Some(err);
                                    continue;
                                }
                            }
                        }
                    }

                    let class = classify_error(None, &err);
                    if class == ErrorClass::Permanent {
                        self.progress.on_error(&url, &err);
                        return Err(err);
                    }
                    tracing::debug!(attempt, "transient error, will retry: {}", err);
                    last_err = Some(err);
                }
            }
        }

        let err = last_err.unwrap_or_else(|| anyhow::anyhow!("transfer failed after retries"));
        self.progress.on_error(&url, &err);
        Err(err)
    }

    /// Execute a single transfer directly via the protocol layer.
    ///
    /// This is the lower-level path used for HEAD requests and transfers
    /// that don't need retry wrapping. Bandwidth limiting and hash
    /// verification (when the body is buffered) are still applied.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL scheme is unsupported, the protocol
    /// operation fails, or the buffered body fails hash verification.
    async fn execute_direct(&self, request: &TransferRequest) -> Result<TransferResult> {
        let url = &request.url;
        let host = extract_host(url).unwrap_or_else(|| "unknown".to_string());
        let credential = self.auth.get(url);
        let proto = protocol::for_url(url)?;

        let _permit = self.pool.acquire(&host).await;

        let mut result = proto.execute(request, credential.as_ref()).await?;

        // Bandwidth limiting.
        if let Some(ref limiter) = self.bandwidth {
            limiter.consume(result.bytes_transferred).await;
        }

        // Hash verification on body if available.
        if let (Some(ref spec), Some(ref body)) = (&request.hash, &result.body) {
            let mut hasher = StreamingHasher::with_expected(spec.algorithm, &spec.expected);
            hasher.update(body);
            let hash_result = hasher.finalize();
            result.hash = Some(hash_result.hex.clone());

            if let Some(false) = hash_result.matched {
                anyhow::bail!(
                    "hash mismatch for {}: expected {}, got {}",
                    url,
                    spec.expected,
                    hash_result.hex
                );
            }
        }

        Ok(result)
    }

    /// Execute multiple transfers in parallel.
    ///
    /// Concurrency is bounded by the connection pool's per-host and
    /// global limits (permits are acquired before each task is
    /// spawned). Each transfer is retried independently per the
    /// engine's [`RetryConfig`]. The returned vector has one
    /// `Result` per request, in the same order as the input; the call
    /// itself never fails as a whole, and a panicked transfer task is
    /// reported as an `Err` for that entry.
    ///
    /// Note: batch transfers currently buffer each response in memory
    /// -- the per-request `body`, `hash`, and `output` settings are
    /// not honored on this path (only `url`, `method`, `headers`, and
    /// `resume` are). Use [`execute`](TransferEngine::execute) for
    /// file output or hash verification.
    pub async fn execute_batch(
        &self,
        requests: Vec<TransferRequest>,
        progress: Option<Box<dyn BatchProgressHandler>>,
    ) -> Vec<Result<TransferResult>> {
        if requests.is_empty() {
            return Vec::new();
        }

        let total = requests.len();
        let progress: Arc<dyn BatchProgressHandler> =
            Arc::from(progress.unwrap_or_else(|| Box::new(NoopProgress)));
        let completed = Arc::new(AtomicUsize::new(0));
        let total_bytes = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::with_capacity(total);

        for (index, request) in requests.into_iter().enumerate() {
            let progress = Arc::clone(&progress);
            let completed = Arc::clone(&completed);
            let total_bytes = Arc::clone(&total_bytes);

            let url = request.url.clone();
            let method = request.method;
            let headers = request.headers.clone();
            let resume = request.resume;
            let maximum_bytes = request.maximum_bytes;
            let host = extract_host(&url).unwrap_or_else(|| "unknown".to_string());
            let credential = self.auth.get(&url);
            let retry_config = self.retry.clone();

            let proto = match protocol::for_url(&url) {
                Ok(p) => p,
                Err(e) => {
                    handles.push(tokio::spawn(async move { Err(e) }));
                    continue;
                }
            };

            // Acquire pool permit before spawning to respect limits.
            let permit = self.pool.acquire(&host).await;

            let handle = tokio::spawn(async move {
                let _permit = permit;
                progress.on_transfer_start(index, &url, None);

                let mut last_err: Option<anyhow::Error> = None;
                let mut success_result: Option<TransferResult> = None;

                for attempt in 0..retry_config.max_attempts {
                    if attempt > 0 {
                        let delay = retry::compute_retry_delay(&retry_config, attempt - 1);
                        tokio::time::sleep(delay).await;
                    }

                    let exec_request = TransferRequest {
                        url: url.clone(),
                        method,
                        headers: headers.clone(),
                        body: None,
                        hash: None,
                        maximum_bytes,
                        resume,
                        output: TransferOutput::Memory,
                    };

                    match proto.execute(&exec_request, credential.as_ref()).await {
                        Ok(result) => {
                            progress.on_transfer_progress(
                                index,
                                result.bytes_transferred,
                                result.content_length,
                            );
                            success_result = Some(result);
                            break;
                        }
                        Err(err) => {
                            let class = classify_error(None, &err);
                            if class == ErrorClass::Permanent {
                                last_err = Some(err);
                                break;
                            }
                            last_err = Some(err);
                        }
                    }
                }

                let result = match success_result {
                    Some(r) => {
                        progress.on_transfer_complete(index, r.bytes_transferred);
                        total_bytes.fetch_add(r.bytes_transferred, Ordering::Relaxed);
                        Ok(r)
                    }
                    None => {
                        let err = last_err
                            .unwrap_or_else(|| anyhow::anyhow!("transfer failed after retries"));
                        progress.on_transfer_error(index, &err);
                        Err(err)
                    }
                };

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                progress.on_batch_progress(done, total, total_bytes.load(Ordering::Relaxed));

                result
            });

            handles.push(handle);
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(anyhow::anyhow!("transfer task panicked: {e}"))),
            }
        }

        results
    }

    /// HEAD request -- check existence and get content-length.
    ///
    /// For most protocols a missing resource is reported as a result
    /// with status 404 rather than an error, so callers can probe for
    /// existence.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL scheme is unsupported or the
    /// underlying protocol operation fails (e.g. connection or
    /// authentication failure). No retries are performed.
    pub async fn head(&self, url: &str) -> Result<TransferResult> {
        let request = TransferRequest::head(url);
        self.execute_direct(&request).await
    }

    /// Batch HEAD requests in parallel.
    ///
    /// Returns one `Result` per URL, in input order; see
    /// [`execute_batch`](TransferEngine::execute_batch) for the
    /// concurrency and retry semantics.
    pub async fn head_batch(&self, urls: &[&str]) -> Vec<Result<TransferResult>> {
        let requests: Vec<TransferRequest> =
            urls.iter().map(|url| TransferRequest::head(url)).collect();
        self.execute_batch(requests, None).await
    }
}

impl std::fmt::Debug for TransferEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferEngine")
            .field("pool", &self.pool)
            .field("auth", &self.auth)
            .field("bandwidth", &self.bandwidth)
            .field("retry", &self.retry)
            .finish()
    }
}

/// Extract the host from a URL string.
fn extract_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TransferEngineConfig::default();
        assert_eq!(config.max_bandwidth, None);
        assert_eq!(config.min_speed, None);
        assert_eq!(config.min_speed_duration, Duration::from_secs(30));
    }

    #[test]
    fn test_engine_creation() {
        let engine = TransferEngine::new(TransferEngineConfig::default());
        let stats = engine.pool().stats();
        assert_eq!(stats.total_active, 0);
    }

    #[test]
    fn test_engine_with_bandwidth() {
        let config = TransferEngineConfig {
            max_bandwidth: Some(1024 * 1024),
            ..Default::default()
        };
        let engine = TransferEngine::new(config);
        assert!(engine.bandwidth.is_some());
    }

    #[test]
    fn test_engine_with_min_speed() {
        let config = TransferEngineConfig {
            min_speed: Some(1024),
            min_speed_duration: Duration::from_secs(10),
            ..Default::default()
        };
        let engine = TransferEngine::new(config);
        assert_eq!(engine.min_speed, Some(1024));
        assert_eq!(engine.min_speed_duration, Duration::from_secs(10));
    }

    #[test]
    fn test_engine_auth() {
        let engine = TransferEngine::new(TransferEngineConfig::default());
        engine.auth().set(
            "example.com",
            crate::auth::Credential::Bearer {
                token: "test".to_string(),
                refresh: None,
            },
        );
        assert!(engine.auth().get("https://example.com/path").is_some());
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(extract_host("s3://bucket/key"), Some("bucket".to_string()));
        assert_eq!(extract_host("not-a-url"), None);
    }

    #[tokio::test]
    async fn test_execute_batch_empty() {
        let engine = TransferEngine::new(TransferEngineConfig::default());
        let results = engine.execute_batch(Vec::new(), None).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_head_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let url = format!("file://{}", file_path.display());
        let engine = TransferEngine::new(TransferEngineConfig::default());
        let result = engine.head(&url).await.unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.content_length, Some(5));
    }

    #[tokio::test]
    async fn test_head_nonexistent() {
        let engine = TransferEngine::new(TransferEngineConfig::default());
        let result = engine
            .head("file:///tmp/aos_net_test_nonexistent_12345")
            .await
            .unwrap();
        assert_eq!(result.status, 404);
    }

    #[tokio::test]
    async fn test_execute_file_get_memory() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let url = format!("file://{}", file_path.display());
        let engine = TransferEngine::new(TransferEngineConfig::default());
        let result = engine.execute(TransferRequest::get(&url)).await.unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.body.unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn test_execute_file_get_to_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        std::fs::write(&src_path, "file content").unwrap();

        let url = format!("file://{}", src_path.display());
        let engine = TransferEngine::new(TransferEngineConfig::default());
        let result = engine
            .execute(TransferRequest::get_to_file(&url, dst_path.clone()))
            .await
            .unwrap();
        assert_eq!(result.status, 200);
        assert!(result.body.is_none());
        assert_eq!(std::fs::read_to_string(&dst_path).unwrap(), "file content");
    }

    #[tokio::test]
    async fn test_execute_file_get_with_hash_correct() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let url = format!("file://{}", file_path.display());
        let engine = TransferEngine::new(TransferEngineConfig::default());

        let result = engine
            .execute(TransferRequest::get(&url).with_hash(
                crate::types::HashAlgorithm::Sha256,
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ))
            .await
            .unwrap();
        assert_eq!(
            result.hash.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }

    #[tokio::test]
    async fn test_execute_file_get_with_hash_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let url = format!("file://{}", file_path.display());
        let engine = TransferEngine::new(TransferEngineConfig::default());

        let err = engine
            .execute(TransferRequest::get(&url).with_hash(
                crate::types::HashAlgorithm::Sha256,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("hash mismatch"));
    }

    #[tokio::test]
    async fn test_execute_file_get_to_file_with_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        std::fs::write(&src_path, "hello").unwrap();

        let url = format!("file://{}", src_path.display());
        let engine = TransferEngine::new(TransferEngineConfig::default());

        // Correct hash with file output -- proves streaming hash works on file output.
        let result = engine
            .execute(
                TransferRequest::get_to_file(&url, dst_path.clone()).with_hash(
                    crate::types::HashAlgorithm::Sha256,
                    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                ),
            )
            .await
            .unwrap();
        assert_eq!(
            result.hash.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
        assert_eq!(std::fs::read_to_string(&dst_path).unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_execute_rejects_response_over_maximum_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "five!").unwrap();

        let url = format!("file://{}", file_path.display());
        let engine = TransferEngine::new(TransferEngineConfig::default());
        let err = engine
            .execute(TransferRequest::get(&url).with_maximum_bytes(4))
            .await
            .unwrap_err();

        assert!(format!("{err}").contains("exceeds the 4 byte limit"));
    }

    #[tokio::test]
    async fn test_execute_file_get_callback() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "callback test").unwrap();

        let url = format!("file://{}", file_path.display());
        let engine = TransferEngine::new(TransferEngineConfig::default());

        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received);

        let request = TransferRequest {
            url: url.clone(),
            method: crate::types::Method::Get,
            headers: Vec::new(),
            body: None,
            hash: None,
            maximum_bytes: None,
            resume: false,
            output: TransferOutput::Callback(Box::new(move |data| {
                received_clone.lock().unwrap().extend_from_slice(data);
                Ok(())
            })),
        };

        let result = engine.execute(request).await.unwrap();
        assert_eq!(result.status, 200);
        assert!(result.bytes_transferred > 0);
        // Body should be None for callback output.
        assert!(result.body.is_none());

        let data = received.lock().unwrap();
        assert_eq!(data.as_slice(), b"callback test");
    }

    #[tokio::test]
    async fn test_execute_with_bandwidth() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "bandwidth test data").unwrap();

        let config = TransferEngineConfig {
            max_bandwidth: Some(1024 * 1024), // 1MB/s (fast enough to not slow test)
            ..Default::default()
        };
        let engine = TransferEngine::new(config);
        let url = format!("file://{}", file_path.display());
        let result = engine.execute(TransferRequest::get(&url)).await.unwrap();
        assert_eq!(result.body.unwrap(), b"bandwidth test data");
    }

    #[tokio::test]
    async fn test_progress_fires_per_chunk() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "progress data").unwrap();

        let progress_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls = Arc::clone(&progress_calls);

        struct TestProgress {
            calls: Arc<std::sync::Mutex<Vec<(String, u64)>>>,
        }
        impl crate::progress::ProgressHandler for TestProgress {
            fn on_start(&self, _url: &str, _total: Option<u64>) {}
            fn on_progress(&self, url: &str, bytes: u64, _total: Option<u64>) {
                self.calls.lock().unwrap().push((url.to_string(), bytes));
            }
            fn on_complete(&self, _url: &str, _bytes: u64) {}
            fn on_error(&self, _url: &str, _error: &anyhow::Error) {}
        }

        let mut engine = TransferEngine::new(TransferEngineConfig::default());
        engine.set_progress(Box::new(TestProgress { calls }));

        let url = format!("file://{}", file_path.display());
        let _result = engine.execute(TransferRequest::get(&url)).await.unwrap();

        let calls = progress_calls.lock().unwrap();
        // At least one progress call should have been made.
        assert!(!calls.is_empty());
        // The last call should have the total bytes.
        assert_eq!(calls.last().unwrap().1, 13); // "progress data" = 13 bytes
    }
}
