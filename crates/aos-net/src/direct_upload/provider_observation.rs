//! Opt-in application observations for actual provider UploadPart attempts.
//!
//! Version 2 records retain process-local first/last positive offered chunks.
//! These records describe chunks offered to reqwest and reply chunks exposed to
//! this caller. They do not measure TLS framing, billed wire bytes, remote body
//! consumption or durable settlement. Executable and run custody are independent.
//!
//! ```text
//! direct_upload_part_application_observation {"version":2,"purpose":"upload_part",...}
//! ```

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    task::{Context, Poll},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use futures_util::Stream;
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

use super::provider::ProviderContext;
use aos_proto_types::direct_upload::DirectPart;

const MAX_RECORD_BYTES: usize = 4096;
static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(0);
static CLOCK_ORIGIN: OnceLock<Instant> = OnceLock::new();

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Pending,
    Accepted,
    Refused,
    Unknown,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    version: u32,
    purpose: &'static str,
    observer_source_sha256: String,
    process_id: u32,
    attempt_ordinal: u64,
    started_at_millis: Option<u64>,
    completed_at_millis: Option<u64>,
    /// Process-local elapsed time; controller calibration remains independent.
    monotonic_elapsed_ns: Option<String>,
    offered_first_elapsed_ns: Option<String>,
    offered_last_elapsed_ns: Option<String>,
    session_sha256: String,
    original_sha256: String,
    client_operation_sha256: String,
    placement_sha256: Option<String>,
    part_sha256: Option<String>,
    provider_origin_sha256: String,
    provider_path_sha256: String,
    offered: Option<Prefix>,
    reply: Option<Prefix>,
    status: Option<u16>,
    etag_sha256: Option<String>,
    outcome: Outcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Prefix {
    bytes: u64,
    sha256: String,
    eof: bool,
    failed: bool,
    overflow: bool,
}

#[derive(Default)]
struct Facts {
    bytes: u64,
    hash: Sha256,
    eof: bool,
    failed: bool,
    overflow: bool,
    first_elapsed_ns: Option<u64>,
    last_elapsed_ns: Option<u64>,
}

impl Facts {
    fn chunk(&mut self, bytes: &[u8]) {
        self.hash.update(bytes);
        match self.bytes.checked_add(bytes.len() as u64) {
            Some(total) => self.bytes = total,
            None => self.overflow = true,
        }
    }

    fn offered_chunk(&mut self, bytes: &[u8]) {
        let first_positive_chunk = self.bytes == 0;
        self.chunk(bytes);
        if !bytes.is_empty() {
            let elapsed = elapsed_ns();
            if first_positive_chunk {
                self.first_elapsed_ns = elapsed;
            }
            self.last_elapsed_ns = elapsed;
        }
    }

    fn snapshot(&self) -> Prefix {
        Prefix {
            bytes: self.bytes,
            sha256: hex::encode(self.hash.clone().finalize()),
            eof: self.eof,
            failed: self.failed,
            overflow: self.overflow,
        }
    }
}

/// Owns one locally attempted dispatch; dropping it preserves unknown outcome.
pub(super) struct Attempt {
    record: Record,
    offered: Arc<Mutex<Facts>>,
    reply: Facts,
    dispatched: bool,
    #[cfg(test)]
    captured: Arc<Mutex<Vec<String>>>,
}

impl Attempt {
    pub(super) fn configured(
        context: &ProviderContext,
        part: &DirectPart,
        url: &Url,
    ) -> Option<Self> {
        if std::env::var_os("AOS_DIRECT_APPLICATION_LEDGER").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return None;
        }
        Some(Self::new(context, part, url))
    }

    fn new(context: &ProviderContext, part: &DirectPart, url: &Url) -> Self {
        let mut source = Sha256::new();
        source.update(include_bytes!("provider.rs"));
        source.update(include_bytes!("provider_observation.rs"));
        Self {
            record: Record {
                version: 2,
                purpose: "upload_part",
                observer_source_sha256: hex::encode(source.finalize()),
                process_id: std::process::id(),
                attempt_ordinal: NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed),
                started_at_millis: None,
                completed_at_millis: None,
                monotonic_elapsed_ns: None,
                offered_first_elapsed_ns: None,
                offered_last_elapsed_ns: None,
                session_sha256: digest(context.session.session_id.as_bytes()),
                original_sha256: digest(context.session.logical_fingerprint.as_bytes()),
                client_operation_sha256: digest(context.intent.client_operation_id.as_bytes()),
                placement_sha256: serde_json::to_vec(&context.placement)
                    .ok()
                    .map(|v| digest(&v)),
                part_sha256: serde_json::to_vec(part).ok().map(|v| digest(&v)),
                provider_origin_sha256: digest(url.origin().ascii_serialization().as_bytes()),
                provider_path_sha256: digest(url.path().as_bytes()),
                offered: None,
                reply: None,
                status: None,
                etag_sha256: None,
                outcome: Outcome::Pending,
            },
            offered: Arc::new(Mutex::new(Facts::default())),
            reply: Facts::default(),
            dispatched: false,
            #[cfg(test)]
            captured: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(super) fn offered<S>(&self, stream: S) -> Offered<S> {
        Offered {
            inner: Box::pin(stream),
            facts: Arc::clone(&self.offered),
        }
    }

    pub(super) fn dispatch(&mut self) {
        self.dispatched = true;
        self.record.started_at_millis = now();
        self.emit();
        self.record.outcome = Outcome::Unknown;
    }

    pub(super) fn status(&mut self, status: u16) {
        self.record.status = Some(status);
        if matches!(status, 401 | 403) {
            self.record.outcome = Outcome::Refused;
        }
    }

    pub(super) fn etag(&mut self, etag: &str) {
        self.record.etag_sha256 = Some(digest(etag.as_bytes()));
    }

    pub(super) fn reply_chunk(&mut self, bytes: &[u8]) {
        self.reply.chunk(bytes);
    }

    pub(super) fn reply_eof(&mut self) {
        self.reply.eof = true;
    }

    pub(super) fn reply_failed(&mut self) {
        self.reply.failed = true;
    }

    pub(super) fn accepted(&mut self) {
        self.record.outcome = Outcome::Accepted;
    }

    fn emit(&mut self) {
        self.record.monotonic_elapsed_ns = elapsed_ns().map(|value| value.to_string());
        let offered = self.offered.lock().ok();
        self.record.offered = offered.as_ref().map(|facts| facts.snapshot());
        self.record.offered_first_elapsed_ns = offered
            .as_ref()
            .and_then(|facts| facts.first_elapsed_ns)
            .map(|value| value.to_string());
        self.record.offered_last_elapsed_ns = offered
            .as_ref()
            .and_then(|facts| facts.last_elapsed_ns)
            .map(|value| value.to_string());
        drop(offered);
        self.record.reply = Some(self.reply.snapshot());
        if let Ok(json) = serde_json::to_string(&self.record) {
            if json.len() <= MAX_RECORD_BYTES {
                #[cfg(test)]
                if let Ok(mut capture) = self.captured.lock() {
                    capture.push(json.clone());
                }
                tracing::info!(target: "aos_direct_application_ledger", "direct_upload_part_application_observation {}", json);
            }
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if self.dispatched {
            self.record.completed_at_millis = now();
            self.emit();
        }
    }
}

/// Hashes only chunks returned by the already budgeted source stream.
pub(super) struct Offered<S> {
    inner: Pin<Box<S>>,
    facts: Arc<Mutex<Facts>>,
}

impl<S: Stream<Item = Result<Bytes, std::io::Error>>> Stream for Offered<S> {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_next(context);
        if let Ok(mut facts) = this.facts.lock() {
            match &result {
                Poll::Ready(Some(Ok(bytes))) => facts.offered_chunk(bytes),
                Poll::Ready(Some(Err(_))) => facts.failed = true,
                Poll::Ready(None) => facts.eof = true,
                Poll::Pending => {}
            }
        }
        result
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// A bounded process-local clock avoids assigning remote UTC authority. The
// hosted controller must retain its own process-start/first-record brackets.
fn elapsed_ns() -> Option<u64> {
    let origin = CLOCK_ORIGIN.get_or_init(Instant::now);
    Instant::now()
        .checked_duration_since(*origin)
        .and_then(|elapsed| elapsed.as_nanos().try_into().ok())
}

fn now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| time.as_millis().try_into().ok())
}

#[cfg(test)]
mod tests;
