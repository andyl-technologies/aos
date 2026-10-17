//! Value-free client counters for control attempts and direct provider overlap.
//!
//! These are client observations, not proof of provider effects, wire bytes or
//! Native bandwidth confinement. Failed and cancelled dispatched attempts count;
//! bytes count only a successful bounded provider response with an accepted ETag.
//! Fanout counts actual dispatched request lifetimes, not offered scheduler work.
//! Validated logical targets and source commitments stay private and disappear
//! when their last attempt drops. Metadata covers LeafMetadata and Visibility;
//! single-part Content participates only in the existing aggregate counters.
//!
//! Terminal counters append four peaks, with `unavailable` for lost telemetry:
//!
//! ```text
//! max_active_bulk_files=2 max_bulk_part_requests_per_file=4 max_active_metadata_files=32 max_active_metadata_requests=32
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A fixed control category without object, actor, token or URL labels.
#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum DirectControlKind {
    /// Authenticated target discovery.
    Capabilities,
    /// Logical direct-session admission.
    Begin,
    /// Sparse original-session status.
    Status,
    /// Private-stage part capability issuance or exact replay.
    Grant,
    /// Original-grant provider receipt reporting.
    Report,
    /// Original staging/final completion replay.
    Complete,
    /// Explicit original-session abort.
    Abort,
    /// Genuine current actor and transport-policy proof.
    Identity,
    /// Original manifest owner admission.
    ManifestBegin,
    /// Bounded original manifest inventory append.
    ManifestAppend,
    /// Original full inventory sealing.
    ManifestSeal,
    /// Public publication commit after the staging barrier.
    PublicationCommit,
    /// Registry/parent/publication metadata reads.
    MetadataRead,
}

const CONTROL_KINDS: usize = 13;
const MAX_ACTIVE_FILE_IDENTITIES: usize = 64;

/// A class derived from the already validated admission, without exported labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProviderFileKind {
    /// Multipart Content requests for one admitted logical file.
    Bulk,
    /// LeafMetadata or Visibility requests for one admitted logical file.
    Metadata,
    /// Requests outside the two measured file classes.
    Other,
}

// This coordinate deliberately excludes session, placement and operation IDs.
// A second attempt for the same logical target/source remains the same file.
pub(super) fn provider_file(
    intent: &aos_proto_types::direct_upload::DirectUploadIntent,
) -> (Option<String>, ProviderFileKind) {
    use aos_proto_types::direct_upload::DirectDependencyPhase;

    let kind = match intent.dependency_phase {
        DirectDependencyPhase::LeafMetadata | DirectDependencyPhase::Visibility => {
            ProviderFileKind::Metadata
        }
        DirectDependencyPhase::Content if intent.byte_size.get() > intent.part_size.get() => {
            ProviderFileKind::Bulk
        }
        _ => ProviderFileKind::Other,
    };
    let file =
        serde_json::to_string(&(&intent.target, &intent.expected_sha256, intent.byte_size)).ok();
    (file, kind)
}

#[derive(Default)]
struct Fanout {
    files: BTreeMap<String, (ProviderFileKind, u64)>,
    maxima: [u64; 4],
}

// Metrics may appear in ordinary Debug output; private identities must not.
impl fmt::Debug for Fanout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Fanout")
            .field("maxima", &self.maxima)
            .finish_non_exhaustive()
    }
}

impl Fanout {
    fn start(&mut self, file: &str, kind: ProviderFileKind) -> Option<()> {
        if kind == ProviderFileKind::Other {
            return Some(());
        }
        if !self.files.contains_key(file) && self.files.len() >= MAX_ACTIVE_FILE_IDENTITIES {
            return None;
        }
        if kind == ProviderFileKind::Metadata {
            self.files
                .values()
                .filter(|value| value.0 == kind)
                .try_fold(1u64, |total, value| total.checked_add(value.1))?;
        }
        let active = self.files.entry(file.to_owned()).or_insert((kind, 0));
        if active.0 != kind {
            return None;
        }
        active.1 = active.1.checked_add(1)?;

        let bulk_files = self
            .files
            .values()
            .filter(|value| value.0 == ProviderFileKind::Bulk)
            .count() as u64;
        let bulk_parts = self
            .files
            .values()
            .filter(|value| value.0 == ProviderFileKind::Bulk)
            .map(|value| value.1)
            .max()
            .unwrap_or(0);
        let metadata_files = self
            .files
            .values()
            .filter(|value| value.0 == ProviderFileKind::Metadata)
            .count() as u64;
        let metadata_requests = self
            .files
            .values()
            .filter(|value| value.0 == ProviderFileKind::Metadata)
            .try_fold(0u64, |total, value| total.checked_add(value.1))?;
        for (maximum, observed) in
            self.maxima
                .iter_mut()
                .zip([bulk_files, bulk_parts, metadata_files, metadata_requests])
        {
            *maximum = (*maximum).max(observed);
        }
        Some(())
    }

    fn finish(&mut self, file: &str) -> Option<()> {
        let active = self.files.get_mut(file)?;
        active.1 = active.1.checked_sub(1)?;
        if active.1 == 0 {
            self.files.remove(file);
        }
        Some(())
    }
}

struct ObservedPeak(Option<u64>);

impl fmt::Display for ObservedPeak {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => value.fmt(formatter),
            None => formatter.write_str("unavailable"),
        }
    }
}

/// Shared counters whose bounded internal file coordinates are never exported.
#[derive(Debug, Default)]
pub struct DirectTransferMetrics {
    controls: [AtomicU64; CONTROL_KINDS],
    attempts: AtomicU64,
    successes: AtomicU64,
    bytes: AtomicU64,
    active: AtomicU64,
    maximum_active: AtomicU64,
    fanout: Mutex<Fanout>,
    fanout_unavailable: AtomicBool,
}

/// A point-in-time value-free client observation, without server proof claims.
#[derive(Debug, Clone, Copy)]
pub struct DirectTransferSummary {
    controls: [u64; CONTROL_KINDS],
    /// Dispatched provider attempts, including failures and cancellations.
    pub provider_attempts: u64,
    /// Attempts with a successful bounded response and accepted ETag.
    pub provider_successes: u64,
    /// Declared payload bytes associated with those successful responses.
    pub acknowledged_payload_bytes: u64,
    /// Provider requests currently in progress at this observation.
    pub active_provider_requests: u64,
    /// Maximum simultaneously dispatched provider requests.
    pub maximum_active_provider_requests: u64,
    /// Peak simultaneously dispatched multipart Content files, or unavailable.
    pub maximum_active_bulk_files: Option<u64>,
    /// Peak dispatched part requests for one multipart Content file, or unavailable.
    pub maximum_bulk_part_requests_per_file: Option<u64>,
    /// Peak simultaneously dispatched LeafMetadata or Visibility files, or unavailable.
    pub maximum_active_metadata_files: Option<u64>,
    /// Peak simultaneously dispatched metadata requests, or unavailable.
    pub maximum_active_metadata_requests: Option<u64>,
}

impl DirectTransferSummary {
    /// Returns dispatched calls for one closed control category, including retries.
    pub fn control_attempts(&self, kind: DirectControlKind) -> u64 {
        self.controls[kind as usize]
    }
}

impl fmt::Display for DirectTransferSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "caps={} begin={} status={} grant={} report={} complete={} abort={} identity={} manifest_begin={} manifest_append={} manifest_seal={} commit={} metadata_read={} provider_attempts={} provider_successes={} acknowledged_bytes={} max_provider_active={} max_active_bulk_files={} max_bulk_part_requests_per_file={} max_active_metadata_files={} max_active_metadata_requests={}",
            self.controls[0],
            self.controls[1],
            self.controls[2],
            self.controls[3],
            self.controls[4],
            self.controls[5],
            self.controls[6],
            self.controls[7],
            self.controls[8],
            self.controls[9],
            self.controls[10],
            self.controls[11],
            self.controls[12],
            self.provider_attempts,
            self.provider_successes,
            self.acknowledged_payload_bytes,
            self.maximum_active_provider_requests,
            ObservedPeak(self.maximum_active_bulk_files),
            ObservedPeak(self.maximum_bulk_part_requests_per_file),
            ObservedPeak(self.maximum_active_metadata_files),
            ObservedPeak(self.maximum_active_metadata_requests)
        )
    }
}

impl DirectTransferMetrics {
    /// Counts one validated control immediately before network dispatch.
    pub fn record_control_attempt(&self, kind: DirectControlKind) {
        self.controls[kind as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Returns observations without consuming or resetting retry history.
    pub fn snapshot(&self) -> DirectTransferSummary {
        let maxima = self.fanout.lock().ok().and_then(|fanout| {
            (!self.fanout_unavailable.load(Ordering::Relaxed)).then_some(fanout.maxima)
        });
        DirectTransferSummary {
            controls: std::array::from_fn(|index| self.controls[index].load(Ordering::Relaxed)),
            provider_attempts: self.attempts.load(Ordering::Relaxed),
            provider_successes: self.successes.load(Ordering::Relaxed),
            acknowledged_payload_bytes: self.bytes.load(Ordering::Relaxed),
            active_provider_requests: self.active.load(Ordering::Relaxed),
            maximum_active_provider_requests: self.maximum_active.load(Ordering::Relaxed),
            maximum_active_bulk_files: maxima.map(|values| values[0]),
            maximum_bulk_part_requests_per_file: maxima.map(|values| values[1]),
            maximum_active_metadata_files: maxima.map(|values| values[2]),
            maximum_active_metadata_requests: maxima.map(|values| values[3]),
        }
    }

    pub(super) fn provider_attempt(
        self: &Arc<Self>,
        file: Option<&str>,
        kind: ProviderFileKind,
    ) -> ProviderAttempt {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.maximum_active.fetch_max(active, Ordering::Relaxed);
        // Telemetry loss must not change provider dispatch or retry behavior.
        let tracked = if kind == ProviderFileKind::Other {
            false
        } else {
            match (file, self.fanout.lock()) {
                (Some(file), Ok(mut fanout))
                    if !self.fanout_unavailable.load(Ordering::Relaxed) =>
                {
                    if fanout.start(file, kind).is_some() {
                        true
                    } else {
                        self.fanout_unavailable.store(true, Ordering::Relaxed);
                        false
                    }
                }
                _ => {
                    self.fanout_unavailable.store(true, Ordering::Relaxed);
                    false
                }
            }
        };
        ProviderAttempt {
            metrics: Arc::clone(self),
            file: file.filter(|_| tracked).map(str::to_owned),
        }
    }
}

pub(super) struct ProviderAttempt {
    metrics: Arc<DirectTransferMetrics>,
    file: Option<String>,
}

impl ProviderAttempt {
    pub(super) fn acknowledge(self, byte_size: u64) {
        self.metrics.successes.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes.fetch_add(byte_size, Ordering::Relaxed);
    }
}

impl Drop for ProviderAttempt {
    fn drop(&mut self) {
        self.metrics.active.fetch_sub(1, Ordering::Relaxed);
        if let Some(file) = &self.file {
            match self.metrics.fanout.lock() {
                Ok(mut fanout) => {
                    if fanout.finish(file).is_none() {
                        self.metrics
                            .fanout_unavailable
                            .store(true, Ordering::Relaxed);
                    }
                }
                Err(poisoned) => {
                    self.metrics
                        .fanout_unavailable
                        .store(true, Ordering::Relaxed);
                    // Lost telemetry is unknown; private lifetime entries still
                    // disappear when their actual guards drop.
                    let _ = poisoned.into_inner().finish(file);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_attempts_and_cancelled_failure_count_without_claiming_success_bytes() {
        let metrics = Arc::new(DirectTransferMetrics::default());
        let barrier = Arc::new(tokio::sync::Barrier::new(4));
        let mut tasks = Vec::new();
        for index in 0..3 {
            let metrics = Arc::clone(&metrics);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                metrics.record_control_attempt(DirectControlKind::Grant);
                let attempt = metrics.provider_attempt(
                    Some(&format!("metadata-{index}")),
                    ProviderFileKind::Metadata,
                );
                barrier.wait().await;
                barrier.wait().await;
                if index < 2 {
                    attempt.acknowledge(100);
                }
                // The third attempt is dropped as a cancelled/failed request.
            }));
        }
        barrier.wait().await;
        assert_eq!(metrics.snapshot().active_provider_requests, 3);
        assert_eq!(metrics.snapshot().maximum_active_provider_requests, 3);
        barrier.wait().await;
        for task in tasks {
            task.await.unwrap();
        }
        let summary = metrics.snapshot();
        assert_eq!(summary.control_attempts(DirectControlKind::Grant), 3);
        assert_eq!(summary.provider_attempts, 3);
        assert_eq!(summary.provider_successes, 2);
        assert_eq!(summary.acknowledged_payload_bytes, 200);
        assert_eq!(summary.active_provider_requests, 0);
        assert!(!summary.to_string().contains("http"));
    }

    #[test]
    fn validated_file_coordinate_merges_attempt_owners_but_distinguishes_sources() {
        use aos_proto_types::direct_upload::{
            DirectDependencyPhase, DirectTransferMode, DirectUploadIntent, DirectUploadTarget,
            WireInteger,
        };

        let mut intent = DirectUploadIntent {
            version: 1,
            client_operation_id: "11".repeat(32),
            target: DirectUploadTarget::CacheObject {
                cache_id: "cache".into(),
                path: "nar/blob".into(),
            },
            expected_sha256: "22".repeat(32),
            byte_size: WireInteger::new(16 * 1024 * 1024),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        };
        intent.validate().unwrap();
        let original = provider_file(&intent);
        assert_eq!(original.1, ProviderFileKind::Bulk);

        intent.client_operation_id = "33".repeat(32);
        assert_eq!(provider_file(&intent), original);
        intent.expected_sha256 = "44".repeat(32);
        assert_ne!(provider_file(&intent).0, original.0);
        intent.byte_size = intent.part_size;
        assert_eq!(provider_file(&intent).1, ProviderFileKind::Other);
        for phase in [
            DirectDependencyPhase::LeafMetadata,
            DirectDependencyPhase::Visibility,
        ] {
            intent.dependency_phase = phase;
            assert_eq!(provider_file(&intent).1, ProviderFileKind::Metadata);
        }
    }

    #[test]
    fn actual_request_lifetimes_distinguish_files_parts_and_metadata() {
        let metrics = Arc::new(DirectTransferMetrics::default());
        let a1 = metrics.provider_attempt(Some("bulk-a"), ProviderFileKind::Bulk);
        let a2 = metrics.provider_attempt(Some("bulk-a"), ProviderFileKind::Bulk);
        let b1 = metrics.provider_attempt(Some("bulk-b"), ProviderFileKind::Bulk);
        let m1 = metrics.provider_attempt(Some("metadata-a"), ProviderFileKind::Metadata);
        let m2 = metrics.provider_attempt(Some("metadata-b"), ProviderFileKind::Metadata);
        let m3 = metrics.provider_attempt(Some("metadata-b"), ProviderFileKind::Metadata);
        let other = metrics.provider_attempt(Some("single-content"), ProviderFileKind::Other);

        let observed = metrics.snapshot();
        assert_eq!(observed.maximum_active_provider_requests, 7);
        assert_eq!(observed.maximum_active_bulk_files, Some(2));
        assert_eq!(observed.maximum_bulk_part_requests_per_file, Some(2));
        assert_eq!(observed.maximum_active_metadata_files, Some(2));
        assert_eq!(observed.maximum_active_metadata_requests, Some(3));

        a1.acknowledge(8);
        drop((a2, b1, m1, m2, m3, other));
        assert_eq!(metrics.snapshot().active_provider_requests, 0);
        assert!(metrics.fanout.lock().unwrap().files.is_empty());
        assert_eq!(metrics.snapshot().provider_successes, 1);
        assert_eq!(metrics.snapshot().maximum_active_bulk_files, Some(2));
    }

    #[tokio::test]
    async fn cancelling_an_actual_guard_removes_its_private_file_before_retry() {
        let metrics = Arc::new(DirectTransferMetrics::default());
        let (ready, started) = tokio::sync::oneshot::channel();
        let owned = Arc::clone(&metrics);
        let task = tokio::spawn(async move {
            let _attempt = owned.provider_attempt(Some("cancelled-file"), ProviderFileKind::Bulk);
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        assert_eq!(metrics.snapshot().active_provider_requests, 1);

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(metrics.fanout.lock().unwrap().files.is_empty());
        let retry = metrics.provider_attempt(Some("cancelled-file"), ProviderFileKind::Bulk);
        retry.acknowledge(16);
        let observed = metrics.snapshot();
        assert_eq!(observed.maximum_bulk_part_requests_per_file, Some(1));
        assert_eq!(observed.provider_attempts, 2);
        assert_eq!(observed.provider_successes, 1);
        assert_eq!(observed.acknowledged_payload_bytes, 16);
        assert_eq!(observed.active_provider_requests, 0);
    }

    #[test]
    fn telemetry_capacity_loss_is_unavailable_without_changing_attempts_or_leaking_ids() {
        let metrics = Arc::new(DirectTransferMetrics::default());
        let mut guards = Vec::new();
        for index in 0..MAX_ACTIVE_FILE_IDENTITIES {
            guards.push(metrics.provider_attempt(
                Some(&format!("private-file-{index}")),
                ProviderFileKind::Metadata,
            ));
        }
        let overflow = metrics.provider_attempt(
            Some("private-capability-do-not-print"),
            ProviderFileKind::Bulk,
        );
        assert_eq!(metrics.snapshot().maximum_active_bulk_files, None);
        assert!(
            metrics
                .snapshot()
                .to_string()
                .contains("max_active_bulk_files=unavailable")
        );
        assert!(!format!("{metrics:?}").contains("private-"));
        overflow.acknowledge(7);
        drop(guards);
        let observed = metrics.snapshot();
        assert_eq!(observed.provider_attempts, 65);
        assert_eq!(observed.provider_successes, 1);
        assert_eq!(observed.active_provider_requests, 0);
        assert!(metrics.fanout.lock().unwrap().files.is_empty());
        assert_eq!(observed.maximum_active_metadata_files, None);

        let poisoned = Arc::new(DirectTransferMetrics::default());
        let attempt =
            poisoned.provider_attempt(Some("private-poisoned-file"), ProviderFileKind::Bulk);
        let shared = Arc::clone(&poisoned);
        assert!(
            std::thread::spawn(move || {
                let _held = shared.fanout.lock().unwrap();
                panic!("synthetic telemetry poison");
            })
            .join()
            .is_err()
        );
        assert_eq!(poisoned.snapshot().maximum_active_bulk_files, None);
        drop(attempt);
        assert_eq!(poisoned.snapshot().active_provider_requests, 0);
        assert!(
            poisoned
                .fanout
                .lock()
                .unwrap_err()
                .into_inner()
                .files
                .is_empty()
        );
        assert!(!format!("{poisoned:?}").contains("private-poisoned-file"));
    }
}
