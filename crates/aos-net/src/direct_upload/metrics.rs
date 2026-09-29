//! Value-free client counters for control attempts and direct provider overlap.
//!
//! These are client observations, not proof of provider effects, wire bytes or
//! Native bandwidth confinement. Failed and cancelled dispatched attempts count;
//! bytes count only a successful bounded provider response with an accepted ETag.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Shared bounded counters that retain no transfer values or credentials.
#[derive(Debug, Default)]
pub struct DirectTransferMetrics {
    controls: [AtomicU64; CONTROL_KINDS],
    attempts: AtomicU64,
    successes: AtomicU64,
    bytes: AtomicU64,
    active: AtomicU64,
    maximum_active: AtomicU64,
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
            "caps={} begin={} status={} grant={} report={} complete={} abort={} identity={} manifest_begin={} manifest_append={} manifest_seal={} commit={} metadata_read={} provider_attempts={} provider_successes={} acknowledged_bytes={} max_provider_active={}",
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
            self.maximum_active_provider_requests
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
        DirectTransferSummary {
            controls: std::array::from_fn(|index| self.controls[index].load(Ordering::Relaxed)),
            provider_attempts: self.attempts.load(Ordering::Relaxed),
            provider_successes: self.successes.load(Ordering::Relaxed),
            acknowledged_payload_bytes: self.bytes.load(Ordering::Relaxed),
            active_provider_requests: self.active.load(Ordering::Relaxed),
            maximum_active_provider_requests: self.maximum_active.load(Ordering::Relaxed),
        }
    }

    pub(super) fn provider_attempt(self: &Arc<Self>) -> ProviderAttempt {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.maximum_active.fetch_max(active, Ordering::Relaxed);
        ProviderAttempt {
            metrics: Arc::clone(self),
        }
    }
}

pub(super) struct ProviderAttempt {
    metrics: Arc<DirectTransferMetrics>,
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
                let attempt = metrics.provider_attempt();
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
}
