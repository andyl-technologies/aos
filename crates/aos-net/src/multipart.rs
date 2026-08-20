//! Backend-neutral multipart upload orchestration.
//!
//! Protocol adapters own only their session RPCs. This module owns source
//! slicing, negotiated-geometry validation, bounded part concurrency,
//! idempotent part and completion retries, continuation offsets, progress, and
//! the choice to abort or preserve staged state after failure.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{stream, StreamExt, TryStreamExt};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::progress::{NoopObserver, TransferEvent, TransferObserver};
use crate::retry::{self, ErrorClass};
use crate::transfer::TransferEngine;

/// Rewindable input accepted by the multipart manager.
#[derive(Debug, Clone)]
pub enum MultipartSource {
    /// Reads every part from a local file.
    File(PathBuf),
    /// Reads every part from a retained open file descriptor.
    FileHandle(Arc<std::fs::File>),
    /// Reads every part from shared immutable memory.
    Bytes(Bytes),
}

impl MultipartSource {
    /// Wraps owned bytes without copying them.
    pub fn bytes(bytes: Vec<u8>) -> Self {
        Self::Bytes(Bytes::from(bytes))
    }

    /// Retains an open file descriptor as the immutable upload source.
    pub fn file(file: std::fs::File) -> Self {
        Self::FileHandle(Arc::new(file))
    }
}

/// Determines what happens to staged remote state after an upload failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MultipartFailurePolicy {
    /// Aborts the remote session after a failed part or completion operation.
    #[default]
    Abort,
    /// Leaves the remote session available for a later invocation to continue.
    Preserve,
}

/// State returned when a backend admits a multipart upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipartSessionState {
    /// The session accepts parts beginning at its advertised part number.
    Active,
    /// Every part is present and only the completion operation remains.
    Completing,
}

/// One backend-specific multipart session plus portable continuation metadata.
#[derive(Debug)]
pub struct MultipartAdmission<S> {
    /// Backend-owned session handle.
    pub session: S,
    /// Negotiated bytes per non-final part.
    pub part_size: u64,
    /// One-based first part that the backend still needs.
    pub next_part_number: u32,
    /// Current lifecycle state.
    pub state: MultipartSessionState,
}

/// Adapts a typed remote multipart protocol to the shared manager.
///
/// `upload_part`, `complete`, and `abort` must be idempotent because the manager
/// may retry them after a response is lost. `begin` is called exactly once so a
/// non-idempotent admission RPC cannot leak duplicate sessions.
#[async_trait]
pub trait MultipartBackend: Send + Sync {
    /// Backend-owned session handle.
    type Session: Send + Sync;
    /// Backend-owned completion record for one uploaded part.
    type Part: Send + Sync;

    /// Begins or discovers the session for an object of `size` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when admission fails or the object is rejected.
    async fn begin(&self, size: u64) -> Result<MultipartAdmission<Self::Session>>;

    /// Uploads one idempotently replaceable part.
    ///
    /// # Errors
    ///
    /// Returns an error when the part is rejected or cannot be transferred.
    async fn upload_part(
        &self,
        session: &Self::Session,
        part_number: u32,
        offset: u64,
        bytes: Bytes,
    ) -> Result<Self::Part>;

    /// Completes the session from the newly uploaded part records.
    ///
    /// A resumed backend may retain earlier part records in its session handle;
    /// callers therefore pass only records produced by this invocation.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot atomically publish the object.
    async fn complete(&self, session: &Self::Session, parts: &[Self::Part]) -> Result<()>;

    /// Aborts staged remote state.
    ///
    /// # Errors
    ///
    /// Returns an error when cleanup cannot be confirmed.
    async fn abort(&self, session: &Self::Session) -> Result<()>;
}

/// Describes one backend-neutral multipart upload.
#[derive(Debug, Clone)]
pub struct MultipartUploadRequest {
    /// Stable destination label included in progress events and errors.
    pub destination: String,
    /// Rewindable upload source.
    pub source: MultipartSource,
    /// Maximum parts uploaded concurrently.
    pub concurrency: usize,
    /// Optional aggregate byte ceiling for concurrently buffered parts.
    pub maximum_in_flight_bytes: Option<u64>,
    /// Smallest accepted negotiated part size.
    pub minimum_part_size: u64,
    /// Largest accepted negotiated part size.
    pub maximum_part_size: u64,
    /// Largest accepted total part count.
    pub maximum_parts: u32,
    /// Remote-state behavior after a terminal failure.
    pub failure_policy: MultipartFailurePolicy,
}

impl MultipartUploadRequest {
    /// Creates a multipart upload with portable conservative defaults.
    pub fn new(destination: impl Into<String>, source: MultipartSource) -> Self {
        Self {
            destination: destination.into(),
            source,
            concurrency: 4,
            maximum_in_flight_bytes: None,
            minimum_part_size: 1,
            maximum_part_size: 5 * 1024 * 1024 * 1024,
            maximum_parts: 10_000,
            failure_policy: MultipartFailurePolicy::Abort,
        }
    }

    /// Sets the maximum number of concurrent part requests.
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Bounds the aggregate payload bytes held by concurrent part requests.
    pub fn with_maximum_in_flight_bytes(mut self, maximum_in_flight_bytes: u64) -> Self {
        self.maximum_in_flight_bytes = Some(maximum_in_flight_bytes);
        self
    }

    /// Restricts backend-negotiated part geometry.
    pub fn with_part_limits(
        mut self,
        minimum_part_size: u64,
        maximum_part_size: u64,
        maximum_parts: u32,
    ) -> Self {
        self.minimum_part_size = minimum_part_size;
        self.maximum_part_size = maximum_part_size;
        self.maximum_parts = maximum_parts;
        self
    }

    /// Selects whether a failed session is aborted or retained for continuation.
    pub fn with_failure_policy(mut self, failure_policy: MultipartFailurePolicy) -> Self {
        self.failure_policy = failure_policy;
        self
    }
}

/// Summary of a completed multipart upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartUploadResult {
    /// Complete object size.
    pub bytes: u64,
    /// Bytes already accepted before this invocation.
    pub resumed_bytes: u64,
    /// Parts uploaded by this invocation.
    pub uploaded_parts: u32,
}

#[derive(Debug, Clone, Copy)]
struct MultipartGeometry {
    size: u64,
    part_size: u64,
    part_count: u32,
    first_part: u32,
    resumed_bytes: u64,
}

impl TransferEngine {
    /// Uploads one object through a typed multipart backend.
    ///
    /// # Errors
    ///
    /// Returns an error when source inspection, backend admission, geometry
    /// validation, part transfer, completion, or required abort cleanup fails.
    pub async fn upload_multipart<B>(
        &self,
        request: MultipartUploadRequest,
        backend: &B,
    ) -> Result<MultipartUploadResult>
    where
        B: MultipartBackend + ?Sized,
    {
        self.upload_multipart_observed(request, backend, &NoopObserver)
            .await
    }

    /// Uploads one observed object through a typed multipart backend.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`upload_multipart`](Self::upload_multipart).
    pub async fn upload_multipart_observed<B>(
        &self,
        request: MultipartUploadRequest,
        backend: &B,
        observer: &dyn TransferObserver,
    ) -> Result<MultipartUploadResult>
    where
        B: MultipartBackend + ?Sized,
    {
        anyhow::ensure!(
            request.concurrency > 0,
            "multipart concurrency must be positive"
        );
        let size = source_size(&request.source).await?;
        anyhow::ensure!(size > 0, "multipart source must not be empty");

        let admission = backend.begin(size).await?;
        let geometry = match validate_geometry(&request, &admission, size) {
            Ok(geometry) => geometry,
            Err(error) => {
                let error =
                    settle_failure(self, &request, backend, &admission.session, error).await;
                observer.observe(TransferEvent::Failed {
                    url: &request.destination,
                    error: &error,
                });
                return Err(error);
            }
        };
        observer.observe(TransferEvent::Started {
            url: &request.destination,
            total_bytes: Some(size),
            resumed_bytes: geometry.resumed_bytes,
        });

        let result = self
            .run_multipart(&request, backend, &admission, geometry, observer)
            .await;
        match result {
            Ok(result) => {
                observer.observe(TransferEvent::Completed {
                    url: &request.destination,
                    transferred_bytes: size,
                });
                Ok(result)
            }
            Err(error) => {
                let error =
                    settle_failure(self, &request, backend, &admission.session, error).await;
                observer.observe(TransferEvent::Failed {
                    url: &request.destination,
                    error: &error,
                });
                Err(error)
            }
        }
    }

    async fn run_multipart<B>(
        &self,
        request: &MultipartUploadRequest,
        backend: &B,
        admission: &MultipartAdmission<B::Session>,
        geometry: MultipartGeometry,
        observer: &dyn TransferObserver,
    ) -> Result<MultipartUploadResult>
    where
        B: MultipartBackend + ?Sized,
    {
        if admission.state == MultipartSessionState::Completing {
            self.retry_multipart_operation(&request.destination, observer, || {
                backend.complete(&admission.session, &[])
            })
            .await?;
            return Ok(MultipartUploadResult {
                bytes: geometry.size,
                resumed_bytes: geometry.size,
                uploaded_parts: 0,
            });
        }

        let transferred = Arc::new(AtomicU64::new(geometry.resumed_bytes));
        let concurrency = request
            .maximum_in_flight_bytes
            .map_or(request.concurrency, |budget| {
                let budget_parts = (budget / geometry.part_size).max(1);
                request
                    .concurrency
                    .min(usize::try_from(budget_parts).unwrap_or(usize::MAX))
            });
        let parts = stream::iter(geometry.first_part..=geometry.part_count)
            .map(|part_number| {
                let source = request.source.clone();
                let transferred = Arc::clone(&transferred);
                async move {
                    let offset = u64::from(part_number - 1)
                        .checked_mul(geometry.part_size)
                        .context("multipart part offset overflow")?;
                    let remaining = geometry
                        .size
                        .checked_sub(offset)
                        .context("multipart part begins beyond the source")?;
                    let part_bytes = remaining.min(geometry.part_size);
                    let bytes = read_source_part(&source, offset, part_bytes).await?;
                    let part = self
                        .retry_multipart_operation(&request.destination, observer, || {
                            backend.upload_part(
                                &admission.session,
                                part_number,
                                offset,
                                bytes.clone(),
                            )
                        })
                        .await?;
                    let complete =
                        transferred.fetch_add(part_bytes, Ordering::Relaxed) + part_bytes;
                    observer.observe(TransferEvent::Progress {
                        url: &request.destination,
                        transferred_bytes: complete,
                        total_bytes: Some(geometry.size),
                    });
                    Ok::<_, anyhow::Error>((part_number, part))
                }
            })
            .buffer_unordered(concurrency)
            .try_collect::<Vec<_>>()
            .await?;

        let mut parts = parts;
        parts.sort_by_key(|(part_number, _)| *part_number);
        let uploaded_parts = u32::try_from(parts.len()).context("multipart part count overflow")?;
        let parts = parts.into_iter().map(|(_, part)| part).collect::<Vec<_>>();
        self.retry_multipart_operation(&request.destination, observer, || {
            backend.complete(&admission.session, &parts)
        })
        .await?;

        Ok(MultipartUploadResult {
            bytes: geometry.size,
            resumed_bytes: geometry.resumed_bytes,
            uploaded_parts,
        })
    }

    async fn retry_multipart_operation<T, F, Fut>(
        &self,
        destination: &str,
        observer: &dyn TransferObserver,
        operation: F,
    ) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let config = self.retry_config();
        let attempts = config.max_attempts.max(1);
        let mut last_error = None;
        for attempt in 0..attempts {
            match operation().await {
                Ok(value) => return Ok(value),
                Err(error) if retry::classify_error(None, &error) == ErrorClass::Permanent => {
                    return Err(error);
                }
                Err(error) if attempt + 1 < attempts => {
                    let delay = retry::compute_retry_delay(config, attempt);
                    observer.observe(TransferEvent::Retrying {
                        url: destination,
                        attempt: attempt + 2,
                        delay,
                        error: &error,
                    });
                    last_error = Some(error);
                    tokio::time::sleep(delay).await;
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("multipart retry exhausted")))
    }
}

fn validate_geometry<S>(
    request: &MultipartUploadRequest,
    admission: &MultipartAdmission<S>,
    size: u64,
) -> Result<MultipartGeometry> {
    anyhow::ensure!(
        request.minimum_part_size > 0 && request.minimum_part_size <= request.maximum_part_size,
        "multipart part limits are invalid"
    );
    anyhow::ensure!(
        request.maximum_parts > 0,
        "multipart part limit must be positive"
    );
    anyhow::ensure!(
        (request.minimum_part_size..=request.maximum_part_size).contains(&admission.part_size),
        "backend negotiated an unsupported multipart part size"
    );
    let part_count_u64 = size.div_ceil(admission.part_size);
    anyhow::ensure!(
        part_count_u64 <= u64::from(request.maximum_parts),
        "multipart upload requires an unsupported number of parts"
    );
    let part_count = u32::try_from(part_count_u64).context("multipart part count overflow")?;
    anyhow::ensure!(
        admission.next_part_number > 0
            && admission.next_part_number
                <= part_count
                    .checked_add(1)
                    .context("multipart continuation part number overflow")?,
        "backend returned invalid multipart progress"
    );
    let resumed_bytes = if admission.state == MultipartSessionState::Completing
        || admission.next_part_number
            == part_count
                .checked_add(1)
                .context("multipart continuation part number overflow")?
    {
        size
    } else {
        u64::from(admission.next_part_number - 1)
            .checked_mul(admission.part_size)
            .context("multipart continuation offset overflow")?
    };
    Ok(MultipartGeometry {
        size,
        part_size: admission.part_size,
        part_count,
        first_part: admission.next_part_number,
        resumed_bytes,
    })
}

async fn source_size(source: &MultipartSource) -> Result<u64> {
    match source {
        MultipartSource::File(path) => {
            let metadata = tokio::fs::metadata(path)
                .await
                .with_context(|| format!("inspecting multipart source {}", path.display()))?;
            anyhow::ensure!(metadata.is_file(), "multipart source is not a regular file");
            Ok(metadata.len())
        }
        MultipartSource::FileHandle(file) => {
            let metadata = file
                .metadata()
                .context("inspecting multipart source descriptor")?;
            anyhow::ensure!(metadata.is_file(), "multipart source is not a regular file");
            Ok(metadata.len())
        }
        MultipartSource::Bytes(bytes) => {
            u64::try_from(bytes.len()).context("multipart source is too large")
        }
    }
}

async fn read_source_part(source: &MultipartSource, offset: u64, size: u64) -> Result<Bytes> {
    let size = usize::try_from(size).context("multipart part exceeds local address space")?;
    match source {
        MultipartSource::File(path) => {
            let mut file = tokio::fs::File::open(path)
                .await
                .with_context(|| format!("opening multipart source {}", path.display()))?;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut bytes = vec![0_u8; size];
            file.read_exact(&mut bytes)
                .await
                .with_context(|| format!("reading multipart source part at offset {offset}"))?;
            Ok(Bytes::from(bytes))
        }
        MultipartSource::FileHandle(file) => {
            let file = file
                .try_clone()
                .context("cloning multipart source descriptor")?;
            let mut file = tokio::fs::File::from_std(file);
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut bytes = vec![0_u8; size];
            file.read_exact(&mut bytes)
                .await
                .with_context(|| format!("reading multipart source part at offset {offset}"))?;
            Ok(Bytes::from(bytes))
        }
        MultipartSource::Bytes(bytes) => {
            let start = usize::try_from(offset).context("multipart part offset is too large")?;
            let end = start
                .checked_add(size)
                .context("multipart part end overflow")?;
            anyhow::ensure!(end <= bytes.len(), "multipart part lies beyond the source");
            Ok(bytes.slice(start..end))
        }
    }
}

async fn settle_failure<B>(
    manager: &TransferEngine,
    request: &MultipartUploadRequest,
    backend: &B,
    session: &B::Session,
    error: anyhow::Error,
) -> anyhow::Error
where
    B: MultipartBackend + ?Sized,
{
    match request.failure_policy {
        MultipartFailurePolicy::Preserve => error.context("multipart upload remains resumable"),
        MultipartFailurePolicy::Abort => {
            match manager
                .retry_multipart_operation(&request.destination, &NoopObserver, || {
                    backend.abort(session)
                })
                .await
            {
                Ok(()) => error.context("multipart upload failed; staged state was aborted"),
                Err(cleanup) => error.context(format!(
                    "multipart upload failed and abort cleanup also failed: {cleanup:#}"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::transfer::TransferEngineConfig;

    struct RecordingBackend {
        uploaded: Mutex<Vec<u32>>,
        aborts: AtomicU64,
        fail_part: Option<u32>,
        next_part: u32,
    }

    #[async_trait]
    impl MultipartBackend for RecordingBackend {
        type Session = ();
        type Part = u32;

        async fn begin(&self, _size: u64) -> Result<MultipartAdmission<Self::Session>> {
            Ok(MultipartAdmission {
                session: (),
                part_size: 3,
                next_part_number: self.next_part,
                state: MultipartSessionState::Active,
            })
        }

        async fn upload_part(
            &self,
            _session: &Self::Session,
            part_number: u32,
            _offset: u64,
            _bytes: Bytes,
        ) -> Result<Self::Part> {
            if self.fail_part == Some(part_number) {
                anyhow::bail!("injected part failure");
            }
            self.uploaded.lock().unwrap().push(part_number);
            Ok(part_number)
        }

        async fn complete(&self, _session: &Self::Session, _parts: &[Self::Part]) -> Result<()> {
            Ok(())
        }

        async fn abort(&self, _session: &Self::Session) -> Result<()> {
            self.aborts.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn resumes_at_backend_part_and_orders_completion() {
        let backend = RecordingBackend {
            uploaded: Mutex::new(Vec::new()),
            aborts: AtomicU64::new(0),
            fail_part: None,
            next_part: 2,
        };
        let manager = TransferEngine::new(TransferEngineConfig::default());
        let request = MultipartUploadRequest::new(
            "test://object",
            MultipartSource::Bytes(Bytes::from_static(b"abcdefgh")),
        )
        .with_concurrency(2)
        .with_part_limits(1, 4, 10);

        let result = manager.upload_multipart(request, &backend).await.unwrap();
        let mut uploaded = backend.uploaded.lock().unwrap().clone();
        uploaded.sort_unstable();
        assert_eq!(uploaded, vec![2, 3]);
        assert_eq!(result.resumed_bytes, 3);
        assert_eq!(result.uploaded_parts, 2);
    }

    #[tokio::test]
    async fn applies_abort_and_preserve_failure_policies() {
        let backend = RecordingBackend {
            uploaded: Mutex::new(Vec::new()),
            aborts: AtomicU64::new(0),
            fail_part: Some(1),
            next_part: 1,
        };
        let mut config = TransferEngineConfig::default();
        config.retry.max_attempts = 1;
        let manager = TransferEngine::new(config);
        let source = MultipartSource::Bytes(Bytes::from_static(b"abcdef"));
        let abort =
            MultipartUploadRequest::new("test://abort", source.clone()).with_part_limits(1, 4, 10);
        assert!(manager.upload_multipart(abort, &backend).await.is_err());
        assert_eq!(backend.aborts.load(Ordering::Relaxed), 1);

        let preserve = MultipartUploadRequest::new("test://preserve", source)
            .with_part_limits(1, 4, 10)
            .with_failure_policy(MultipartFailurePolicy::Preserve);
        assert!(manager.upload_multipart(preserve, &backend).await.is_err());
        assert_eq!(backend.aborts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn invalid_negotiated_geometry_aborts_the_admitted_session() {
        let backend = RecordingBackend {
            uploaded: Mutex::new(Vec::new()),
            aborts: AtomicU64::new(0),
            fail_part: None,
            next_part: 1,
        };
        let manager = TransferEngine::new(TransferEngineConfig::default());
        let request = MultipartUploadRequest::new(
            "test://invalid-geometry",
            MultipartSource::Bytes(Bytes::from_static(b"abcdef")),
        )
        .with_part_limits(4, 8, 10);

        assert!(manager.upload_multipart(request, &backend).await.is_err());
        assert_eq!(backend.aborts.load(Ordering::Relaxed), 1);
        assert!(backend.uploaded.lock().unwrap().is_empty());
    }
}
