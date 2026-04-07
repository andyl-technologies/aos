//! Transfer engine -- the main public API.
//!
//! Orchestrates downloads/uploads using the connection pool, protocol layer,
//! retry logic, hash verification, progress tracking, and bandwidth limiting.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::auth::AuthStore;
use crate::bandwidth::BandwidthLimiter;
use crate::hash::StreamingHasher;
use crate::pool::{ConnectionPool, PoolConfig};
use crate::progress::{BatchProgressHandler, NoopProgress, ProgressHandler};
use crate::protocol;
use crate::retry::{self, classify_error, ErrorClass, RetryConfig};
use crate::types::{TransferOutput, TransferRequest, TransferResult};

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
    pub min_speed: Option<u64>,
    /// How long the speed must be below `min_speed` before aborting.
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
/// reporting, and bandwidth limiting.
pub struct TransferEngine {
    pool: ConnectionPool,
    auth: AuthStore,
    bandwidth: Option<BandwidthLimiter>,
    retry: RetryConfig,
    progress: Box<dyn ProgressHandler>,
}

impl TransferEngine {
    /// Create a new transfer engine with the given configuration.
    pub fn new(config: TransferEngineConfig) -> Self {
        let bandwidth = config.max_bandwidth.map(BandwidthLimiter::new);

        Self {
            pool: ConnectionPool::new(config.pool),
            auth: AuthStore::new(),
            bandwidth,
            retry: config.retry,
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

    /// Execute a single transfer with retry, hash verification, and progress.
    pub async fn execute(&self, request: TransferRequest) -> Result<TransferResult> {
        let url = request.url.clone();
        let hash_spec = request.hash.clone();
        let host = extract_host(&url).unwrap_or_else(|| "unknown".to_string());
        let credential = self.auth.get(&url);
        let proto = protocol::for_url(&url)?;

        self.progress.on_start(&url, None);

        // Manual retry loop (avoids closure lifetime issues with &self).
        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 0..self.retry.max_attempts {
            if attempt > 0 {
                let delay = retry::compute_retry_delay(&self.retry, attempt - 1);
                tracing::debug!(attempt, delay_ms = delay.as_millis(), "retrying");
                tokio::time::sleep(delay).await;
            }

            let _permit = self.pool.acquire(&host).await;

            let exec_request = TransferRequest {
                url: url.clone(),
                method: request.method,
                headers: request.headers.clone(),
                body: None, // Body can't be cloned for retries.
                hash: None, // Hash is checked after protocol execution.
                resume: request.resume,
                output: TransferOutput::Memory,
            };

            match proto.execute(&exec_request, credential.as_ref()).await {
                Ok(mut result) => {
                    // Apply bandwidth limiting.
                    if let Some(ref limiter) = self.bandwidth {
                        limiter.consume(result.bytes_transferred).await;
                    }

                    // Verify hash if specified.
                    if let Some(ref spec) = hash_spec {
                        if let Some(ref body) = result.body {
                            let mut hasher = StreamingHasher::with_expected(
                                spec.algorithm,
                                &spec.expected,
                            );
                            hasher.update(body);
                            let hash_result = hasher.finalize();
                            result.hash = Some(hash_result.hex.clone());

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
                    }

                    self.progress
                        .on_progress(&url, result.bytes_transferred, result.content_length);
                    self.progress.on_complete(&url, result.bytes_transferred);
                    return Ok(result);
                }
                Err(err) => {
                    let class = classify_error(None, &err);
                    if class == ErrorClass::Permanent {
                        self.progress.on_error(&url, &err);
                        return Err(err);
                    }
                    tracing::debug!(
                        attempt,
                        "transient error, will retry: {}",
                        err
                    );
                    last_err = Some(err);
                }
            }
        }

        let err = last_err
            .unwrap_or_else(|| anyhow::anyhow!("transfer failed after retries"));
        self.progress.on_error(&url, &err);
        Err(err)
    }

    /// Execute a single transfer directly via the protocol layer.
    ///
    /// This is the lower-level path used for HEAD requests and transfers
    /// that don't need retry wrapping.
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
            let mut hasher =
                StreamingHasher::with_expected(spec.algorithm, &spec.expected);
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
    /// global limits.
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
                let _permit = permit; // Hold permit until task completes.
                progress.on_transfer_start(index, &url, None);

                // Manual retry loop inside the spawned task.
                let mut last_err: Option<anyhow::Error> = None;
                let mut success_result: Option<TransferResult> = None;

                for attempt in 0..retry_config.max_attempts {
                    if attempt > 0 {
                        let delay =
                            retry::compute_retry_delay(&retry_config, attempt - 1);
                        tokio::time::sleep(delay).await;
                    }

                    let exec_request = TransferRequest {
                        url: url.clone(),
                        method,
                        headers: headers.clone(),
                        body: None,
                        hash: None,
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
                        let err = last_err.unwrap_or_else(|| {
                            anyhow::anyhow!("transfer failed after retries")
                        });
                        progress.on_transfer_error(index, &err);
                        Err(err)
                    }
                };

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                progress.on_batch_progress(
                    done,
                    total,
                    total_bytes.load(Ordering::Relaxed),
                );

                result
            });

            handles.push(handle);
        }

        // Collect results.
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => {
                    results.push(Err(anyhow::anyhow!("transfer task panicked: {e}")))
                }
            }
        }

        results
    }

    /// HEAD request -- check existence and get content-length.
    pub async fn head(&self, url: &str) -> Result<TransferResult> {
        let request = TransferRequest::head(url);
        self.execute_direct(&request).await
    }

    /// Batch HEAD requests in parallel.
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
        assert_eq!(
            extract_host("s3://bucket/key"),
            Some("bucket".to_string())
        );
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
}
