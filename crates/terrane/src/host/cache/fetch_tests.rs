//! Exercises verified lower-tier fallback and a genuinely pending request.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture success and refusal assertions intentionally panic on unexpected outcomes."
)]

use super::{CircuitBreaker, FetchRequirement, fetch_verified};
use crate::{
    repository::MetadataValidator,
    store::{
        ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload, Durability,
        IdentityPrefix, RangeCapability, RefCapability, StoreErrorKind, StoreFailure,
    },
};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
};

#[derive(Default)]
struct TestClock(Mutex<Duration>);

#[async_trait::async_trait]
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + self.monotonic()
    }
    fn monotonic(&self) -> Duration {
        *self.0.lock().unwrap()
    }
    async fn sleep(&self, duration: Duration) -> std::io::Result<()> {
        let mut ticks = self.0.lock().unwrap();
        *ticks = ticks.saturating_add(duration);
        Ok(())
    }
}

struct Source {
    bytes: Option<Vec<u8>>,
    calls: AtomicUsize,
    capabilities: Capabilities,
}

impl Source {
    fn new(bytes: Option<Vec<u8>>) -> Self {
        Self {
            bytes,
            calls: AtomicUsize::new(0),
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::WholeObjectOnly,
                presign: false,
                locality: Default::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }
}

impl CapabilityReport for Source {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl ContentStore for Source {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }
    async fn get(&self, _: &Identity, _: Option<ByteRange>) -> Result<Vec<u8>, StoreFailure> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match &self.bytes {
            Some(bytes) => Ok(bytes.clone()),
            None => std::future::pending().await,
        }
    }
    async fn has(&self, ids: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        Ok(vec![self.bytes.is_some(); ids.len()])
    }
    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Ok(Vec::new())
    }
}

fn circuits(count: usize) -> Vec<CircuitBreaker> {
    (0..count)
        .map(|_| CircuitBreaker::new(1, Duration::from_secs(5)).unwrap())
        .collect()
}

#[tokio::test]
async fn host_cache_fetch_corrupt_first_tier_falls_back_and_opens_its_circuit() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, b"good").unwrap();
    let requirement = FetchRequirement::Chunk {
        identity: &identity,
        length: 4,
        profile: &profile,
        final_chunk: true,
        dictionary: None,
    };
    let sources = [
        Source::new(Some(b"\0evil".to_vec())),
        Source::new(Some(b"\0good".to_vec())),
    ];
    let mut circuits = circuits(2);
    let clock = TestClock::default();
    let validator = MetadataValidator::new(profile.clone());

    assert_eq!(
        fetch_verified(
            &sources,
            &mut circuits,
            &clock,
            Duration::from_secs(10),
            &requirement,
            &validator
        )
        .await
        .unwrap(),
        b"\0good"
    );
    assert_eq!(
        fetch_verified(
            &sources,
            &mut circuits,
            &clock,
            Duration::from_secs(10),
            &requirement,
            &validator
        )
        .await
        .unwrap(),
        b"\0good"
    );
    assert_eq!(sources[0].calls.load(Ordering::Relaxed), 1);
    assert_eq!(sources[1].calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn host_cache_fetch_pending_child_hits_total_deadline() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, b"good").unwrap();
    let requirement = FetchRequirement::Chunk {
        identity: &identity,
        length: 4,
        profile: &profile,
        final_chunk: true,
        dictionary: None,
    };
    let sources = [Source::new(None)];
    let mut circuits = circuits(1);
    let clock = TestClock::default();

    let error = fetch_verified(
        &sources,
        &mut circuits,
        &clock,
        Duration::from_secs(7),
        &requirement,
        &MetadataValidator::new(profile.clone()),
    )
    .await
    .unwrap_err();

    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    assert_eq!(clock.monotonic(), Duration::from_secs(7));
    assert_eq!(sources[0].calls.load(Ordering::Relaxed), 1);
}
