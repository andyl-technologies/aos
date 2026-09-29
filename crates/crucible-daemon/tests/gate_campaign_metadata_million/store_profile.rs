//! Opt-in timings and immutable-read counts for the bounded durable corpus.
//!
//! The wrapper delegates every storage operation, including batch publication,
//! and drains the backend's original authenticating stream. Measurements are
//! host diagnostics and never enter a planner input or campaign record.
//!
//! ```text
//! campaign_store_profile request=1 phase=planner measurements={...}
//! ```

// crucible-lint: allow rust-allow -- Opt-in host diagnostics leave campaign inputs unchanged.
// crucible-lint: allow clippy-disallowed-method -- Instant measures storage diagnostics only.
#![allow(
    clippy::disallowed_methods,
    reason = "Opt-in wall-time diagnostics never enter campaign inputs or records."
)]

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, BlobSource, ByteRange, ContentId, ImmutableBlobBackend,
    PutReceipt, StoreError, StoreGraph,
};

#[derive(Default, serde::Serialize)]
struct Counts {
    calls: u64,
    bytes: u64,
    nanoseconds: u128,
}

#[derive(Default, serde::Serialize)]
struct Measurements {
    operations: BTreeMap<String, Counts>,
    immutable_reads: BTreeMap<String, u64>,
    batch_sizes: BTreeMap<usize, u64>,
}

/// Collects opt-in measurements while preserving the original store operations.
pub(super) struct ProfileBackend {
    inner: Arc<StoreGraph>,
    measured: Arc<Mutex<Measurements>>,
}

impl ProfileBackend {
    /// Wraps the original admitted graph without changing publication behavior.
    pub(super) fn new(inner: Arc<StoreGraph>) -> Self {
        Self {
            inner,
            measured: Arc::new(Mutex::new(Measurements::default())),
        }
    }

    /// Prints and resets the counters after one setup or planner stage.
    ///
    /// # Panics
    ///
    /// Panics if the diagnostic mutex is poisoned or its counters cannot be encoded.
    pub(super) fn report(&self, request: usize, phase: &str) {
        let measured = std::mem::take(&mut *self.measured.lock().expect("profile lock"));
        println!(
            "campaign_store_profile request={request} phase={phase} measurements={}",
            serde_json::to_string(&measured).expect("profile JSON"),
        );
    }

    fn record(&self, operation: &str, started: Instant, bytes: u64) {
        record(&self.measured, operation, started, bytes);
    }
}

fn record(measured: &Mutex<Measurements>, operation: &str, started: Instant, bytes: u64) {
    let elapsed = started.elapsed().as_nanos();
    let mut measured = measured.lock().expect("profile lock");
    let count = measured.operations.entry(operation.to_owned()).or_default();
    count.calls += 1;
    count.bytes += bytes;
    count.nanoseconds += elapsed;
}

impl ImmutableBlobBackend for ProfileBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        let started = Instant::now();
        let result = self.inner.contains(id);
        self.record("contains", started, 0);
        result
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let started = Instant::now();
        let handle = self.inner.read(id, range)?;
        self.record("open-read-handle", started, 0);
        *self
            .measured
            .lock()
            .expect("profile lock")
            .immutable_reads
            .entry(id.encode())
            .or_default() += 1;

        Ok(BlobHandle::new(Arc::new(ProfileSource {
            handle,
            measured: Arc::clone(&self.measured),
        })))
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let started = Instant::now();
        let result = self.inner.put_if_absent(id, source);
        self.record("put-single", started, source.logical_length());
        result
    }

    fn put_many_if_absent(
        &self,
        objects: &[(ContentId, BlobHandle)],
    ) -> Result<Vec<PutReceipt>, StoreError> {
        let started = Instant::now();
        let result = self.inner.put_many_if_absent(objects);
        *self
            .measured
            .lock()
            .expect("profile lock")
            .batch_sizes
            .entry(objects.len())
            .or_default() += 1;
        self.record(
            "put-batch",
            started,
            objects
                .iter()
                .map(|(_, handle)| handle.logical_length())
                .sum(),
        );
        result
    }
}

struct ProfileSource {
    handle: BlobHandle,
    measured: Arc<Mutex<Measurements>>,
}

impl BlobSource for ProfileSource {
    fn logical_length(&self) -> u64 {
        self.handle.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(ProfileReader {
            inner: self.handle.open()?,
            measured: Arc::clone(&self.measured),
        }))
    }
}

struct ProfileReader {
    inner: Box<dyn Read + Send>,
    measured: Arc<Mutex<Measurements>>,
}

impl Read for ProfileReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let started = Instant::now();
        let result = self.inner.read(buffer);
        record(
            &self.measured,
            "stream-read",
            started,
            result.as_ref().map_or(0, |count| *count as u64),
        );
        result
    }
}
