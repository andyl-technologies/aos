//! Checks actual recovered native body reads with the original lower chunk path denied.
//!
//! The fresh actor installs confinement before an executor, reopens the original
//! signed repository and obtains real quota/recovery/Resume owners. The lower
//! wrapper retains that actual backend for metadata and counts every refused
//! chunk read. It never supplies replacement bytes, authority or readiness.

use super::{FixtureResult, MAIN, check_owner, expected_commit, fs};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_linux::{
    configured::NativeCachePlan, configured_sdk, host_cache::NativeReadPolicy, quota_confinement,
};
use terrane_sdk::{
    config::Config,
    role::Role,
    store::{
        ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
        StoreErrorKind, StoreFailure, TokioClock, TokioLocalFs,
    },
    surface::View,
};

struct OfflineChunks<S> {
    original: S,
    chunk_calls: Arc<AtomicUsize>,
    stall_next_chunk: Arc<AtomicBool>,
}

impl<S: CapabilityReport> CapabilityReport for OfflineChunks<S> {
    fn capabilities(&self) -> &Capabilities {
        self.original.capabilities()
    }
}

#[async_trait::async_trait]
impl<S: ContentStore + Send + Sync> ContentStore for OfflineChunks<S> {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if identity.kind() == IdentityKind::Chunk {
            self.chunk_calls.fetch_add(1, Ordering::Relaxed);
            if self.stall_next_chunk.swap(false, Ordering::Relaxed) {
                // Only the actual driver's deadline can finish this attempt.
                // Cancellation drops a lower read with no accepted native work.
                return std::future::pending().await;
            }
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        self.original.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        let mut present = Vec::with_capacity(identities.len());
        for identity in identities {
            match self.get(identity, None).await {
                Ok(_) => present.push(true),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {
                    present.push(false)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(present)
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.original.list(prefix).await
    }
}

/// Runs an explicitly requested fresh-process native cold-recovery check.
///
/// # Errors
/// Rejects missing original trust, failed confinement/recovery, any lower chunk
/// attempt and any mismatch with the setup's actual signed commit and payload.
pub(super) fn run(root: &Path, owner: u32) -> FixtureResult<()> {
    check_owner(root, owner)?;
    let config = Config::parse(&fs::read_to_string(root.join("config.toml"))?)?;
    drop(configured_sdk::preflight(&config, Role::Serve)?);
    let trusted = config
        .local_repository()
        .ok_or("missing trusted repository")?;
    let host = config
        .host_tier()
        .ok_or("missing explicit native host tier")?;
    let lower = host
        .domains
        .get(&trusted.domain)
        .and_then(|domain| domain.cache.as_ref())
        .and_then(|cache| cache.lower)
        .ok_or("missing finite lower policy")?;
    let policy = NativeReadPolicy::new(
        Duration::from_millis(lower.budget_ms),
        lower.failure_threshold,
        Duration::from_millis(lower.probe_interval_ms),
    )?;
    let plan = NativeCachePlan::from_host(host, terrane_format::refs::Locality::default())?;
    let expected = expected_commit(root)?;
    let token = fs::read(root.join("first.cap"))?;
    let installed = Arc::new(quota_confinement::install()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        eprintln!("SDK_OFFLINE_STAGE repository-open");
        let original = config
            .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
            .await?;
        eprintln!("SDK_OFFLINE_STAGE cache-recovery");
        let mut caches = plan.open(Arc::clone(&installed)).await?;
        let cache = caches
            .remove(&trusted.domain)
            .ok_or("missing actual recovered domain")?;
        let chunk_calls = Arc::new(AtomicUsize::new(0));
        let stall_next_chunk = Arc::new(AtomicBool::new(false));
        let payload = super::payload::expected(root)?;
        let boundaries = original.chunk_profile().boundaries(&payload);
        let first = boundaries.first().ok_or("missing actual payload chunk")?;
        let resident = TERRANE_V1.calculate(IdentityKind::Chunk, &payload[first.clone()])?;
        let mut driver = None;
        let repository = original.with_read_driver(|original| {
            let actual = cache.into_content().with_lower(
                OfflineChunks {
                    original: original.clone(),
                    chunk_calls: Arc::clone(&chunk_calls),
                    stall_next_chunk: Arc::clone(&stall_next_chunk),
                },
                policy,
            );
            driver = Some(actual.clone());
            actual
        });
        eprintln!("SDK_OFFLINE_STAGE resident-file");
        for _ in 0..2 {
            let actual = repository
                .read_file(&View::parse(MAIN)?, b"file", &token, "sdk")
                .await?;
            if actual != (expected, payload.clone())
                || chunk_calls.load(Ordering::Relaxed) != 0
            {
                return Err(
                    "native resident read used lower chunks or changed signed payload".into(),
                );
            }
        }
        eprintln!("SDK_OFFLINE_STAGE resident-chunk");
        let driver = driver.ok_or("missing actual shared native driver")?;
        let encoded = driver.get(&resident, None).await?;
        if chunk_calls.load(Ordering::Relaxed) != 0 {
            return Err("resident baseline reached the unavailable lower".into());
        }

        // The source-bound VM supplies this explicit finite policy. These
        // controls use its real timer within the actor's existing deadline.
        if lower.budget_ms != 10_000
            || lower.failure_threshold != 3
            || lower.probe_interval_ms != 5_000
        {
            return Err("unexpected lower deadline/circuit fixture policy".into());
        }
        let missing = TERRANE_V1.calculate(
            IdentityKind::Chunk,
            b"independent native lower deadline and circuit miss",
        )?;
        eprintln!("SDK_OFFLINE_STAGE lower-deadline");
        stall_next_chunk.store(true, Ordering::Relaxed);
        let started = tokio::time::Instant::now();
        let failed = tokio::time::timeout(
            Duration::from_millis(lower.budget_ms + 2_000),
            driver.get(&missing, None),
        )
        .await?;
        require_unavailable(failed)?;
        if started.elapsed() < Duration::from_millis(lower.budget_ms)
            || chunk_calls.load(Ordering::Relaxed) != 1
        {
            return Err("lower stall did not reach the driver's actual deadline".into());
        }
        println!("PASS: actual native driver bounds an indefinitely pending lower read");

        for expected_calls in [2, 3] {
            require_unavailable(driver.get(&missing, None).await)?;
            if chunk_calls.load(Ordering::Relaxed) != expected_calls {
                return Err("lower failure threshold differs from actual attempts".into());
            }
        }
        let opened = tokio::time::Instant::now();
        let shared = driver.clone();
        require_unavailable(shared.get(&missing, None).await)?;
        if chunk_calls.load(Ordering::Relaxed) != 3
            || shared.get(&resident, None).await? != encoded
            || chunk_calls.load(Ordering::Relaxed) != 3
        {
            return Err("open circuit called lower or blocked actual resident content".into());
        }
        println!("PASS: actual shared native circuit blocks lower misses while resident content remains readable");

        tokio::time::sleep_until(opened + Duration::from_millis(lower.probe_interval_ms)).await;
        require_unavailable(shared.get(&missing, None).await)?;
        require_unavailable(driver.get(&missing, None).await)?;
        if chunk_calls.load(Ordering::Relaxed) != 4 {
            return Err("native circuit did not permit exactly one scheduled lower probe".into());
        }
        println!("PASS: actual native circuit permits one bounded scheduled lower probe and reopens on failure");
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    drop(runtime);
    installed.check_current()?;
    result
}

/// Checks the real driver's public failure classification without inspecting state.
fn require_unavailable(result: Result<Vec<u8>, StoreFailure>) -> FixtureResult<()> {
    match result {
        Err(error) if matches!(error.kind(), StoreErrorKind::Unavailable { .. }) => Ok(()),
        _ => Err("native lower miss did not fail unavailable".into()),
    }
}
