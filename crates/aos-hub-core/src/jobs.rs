//! The async job-queue port: deferred post-write propagation (RFC-0004 ch.14
//! Phase D).
//!
//! A write (a publish, a config change) should commit its durable state fast and
//! defer the *expensive propagation* — regenerating the machine surface,
//! rebuilding the global directory projection, delivering webhooks, and
//! re-indexing — to an asynchronous worker. That
//! keeps the synchronous write latency low ("writes can be higher latency, but
//! the durable part is fast") and matches the chapter's split.
//!
//! [`Queue`] is the port both shells implement:
//!
//! - the **Cloudflare Worker** backs it with **Cloudflare Queues** (`WorkerQueue`
//!   producer + an `#[event(queue)]` consumer);
//! - the **native hub** backs it with an in-process runner ([`InMemoryQueue`]
//!   here records jobs; a durable native deployment drains a queue table on a
//!   tokio task).
//!
//! [`Job`] is the wire-free, JSON-serializable unit of deferred work, so the same
//! job list is produced on either shell and consumed by the same handlers.

use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::backend::BackendBounds;

/// One deferred unit of post-write propagation.
///
/// Enqueued synchronously by a write handler and run asynchronously by the
/// queue consumer. Serializable so it crosses the Cloudflare Queues boundary and
/// is single-sourced between the shells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Job {
    /// Runs a bounded pass of durable topology-probe operations.
    RunTopologyProbes,
    /// Regenerate a registry's machine surface (NAR/narinfo pointers) after a
    /// publish.
    RegenerateSurface {
        /// The registry whose surface to regenerate.
        registry_id: i64,
    },
    /// Rebuild the global registry/cache **directory** projection (the instance
    /// home's cached listing — RFC-0004 ch.14 Phase D, `crate::directory`).
    RebuildDirectory,
    /// Re-index a published registry's surface in `HubDb` (the event-driven
    /// counterpart to the Cron indexer).
    Reindex {
        /// The registry to re-index.
        registry_id: i64,
    },
    /// Clears one registry's rebuildable derived index before an operator-led
    /// full re-index. Publication state and stored surface objects are retained.
    ResetIndex {
        /// The registry whose derived index is reset.
        registry_id: i64,
    },
    /// Re-attests one object declared by the current ready publication.
    RefreshPublicationObject {
        /// The registry whose current publication owns the object.
        registry_id: i64,
        /// The exact surface-relative object key to re-attest.
        object_key: String,
    },
    /// Deliver a webhook event to a configured endpoint.
    DeliverWebhook {
        /// Stable delivery identity; queue retries resolve and claim this row.
        delivery_id: String,
    },
}

/// Current durable queue-envelope format.
pub const JOB_ENVELOPE_VERSION: u8 = 2;

/// Resume position carried by a bounded follow-up job.
///
/// The cursor is opaque to the queue. Its job handler defines the cursor's
/// meaning and must reject a cursor that does not belong to the enclosed job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobContinuation {
    /// Zero-based bounded-pass sequence, incremented for each follow-up.
    pub sequence: u32,
    /// Handler-owned opaque resume cursor.
    pub cursor: String,
}

/// Versioned durable queue message with a stable execution identity.
///
/// Cloudflare may deliver a message more than once. `operation_id` remains
/// unchanged across those deliveries and lets the database suppress a replay
/// after the first successful execution. Follow-up chunks receive a
/// deterministic child identity through [`JobEnvelope::continued`], so a
/// crash between enqueue and acknowledgement cannot create duplicate work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEnvelope {
    /// Queue wire-format version.
    pub version: u8,
    /// Stable identity for this exact bounded unit of work.
    pub operation_id: String,
    /// Deferred operation to execute.
    pub job: Job,
    /// Resume position for a bounded continuation, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<JobContinuation>,
}

impl JobEnvelope {
    /// Creates a root envelope with a fresh stable operation identity.
    #[must_use]
    pub fn new(job: Job) -> Self {
        Self {
            version: JOB_ENVELOPE_VERSION,
            operation_id: uuid::Uuid::new_v4().simple().to_string(),
            job,
            continuation: None,
        }
    }

    /// Wraps a legacy message using a deterministic transport identity.
    #[must_use]
    pub fn from_legacy(job: Job, transport_id: &str) -> Self {
        let operation_id = hex::encode(Sha256::digest(
            format!("aos-worker-job-legacy-v2\0{transport_id}").as_bytes(),
        ));
        Self {
            version: JOB_ENVELOPE_VERSION,
            operation_id,
            job,
            continuation: None,
        }
    }

    /// Builds the deterministic next bounded continuation.
    ///
    /// Repeating this call with the same parent, job, and cursor yields the
    /// same identity, which makes enqueue-after-commit retry safe.
    ///
    /// # Errors
    ///
    /// Returns an error when the parent envelope is invalid, the sequence
    /// overflows, the cursor is empty or oversized, or the job cannot be
    /// serialized for identity derivation.
    pub fn continued(&self, job: Job, cursor: String) -> Result<Self> {
        self.validate()?;
        if cursor.is_empty() || cursor.len() > 2_048 {
            bail!("job continuation cursor must contain 1 through 2048 bytes");
        }
        let sequence = self.continuation.as_ref().map_or(Ok(1), |continuation| {
            continuation
                .sequence
                .checked_add(1)
                .context("job continuation sequence overflowed")
        })?;
        let encoded_job = serde_json::to_vec(&job).context("serializing continuation job")?;
        let mut identity = Sha256::new();
        identity.update(b"aos-worker-job-continuation-v2\0");
        identity.update(self.operation_id.as_bytes());
        identity.update(b"\0");
        identity.update(sequence.to_be_bytes());
        identity.update(b"\0");
        identity.update(cursor.as_bytes());
        identity.update(b"\0");
        identity.update(encoded_job);

        Ok(Self {
            version: JOB_ENVELOPE_VERSION,
            operation_id: hex::encode(identity.finalize()),
            job,
            continuation: Some(JobContinuation { sequence, cursor }),
        })
    }

    /// Validates the bounded wire contract before execution.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, malformed operation
    /// identity, or invalid continuation cursor.
    pub fn validate(&self) -> Result<()> {
        if self.version != JOB_ENVELOPE_VERSION {
            bail!("unsupported job envelope version {}", self.version);
        }
        if self.operation_id.len() != 32 && self.operation_id.len() != 64 {
            bail!("job operation identity must contain 32 or 64 hexadecimal bytes");
        }
        if !self
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("job operation identity must be lowercase hexadecimal");
        }
        if let Some(continuation) = &self.continuation {
            if continuation.sequence == 0
                || continuation.cursor.is_empty()
                || continuation.cursor.len() > 2_048
            {
                bail!("job continuation is invalid");
            }
        }
        Ok(())
    }

    /// Returns a stable digest of the operation payload and continuation.
    ///
    /// # Errors
    ///
    /// Returns an error if the envelope is invalid or cannot be serialized.
    pub fn payload_digest(&self) -> Result<String> {
        self.validate()?;
        let payload = serde_json::to_vec(&(&self.job, &self.continuation))
            .context("serializing job payload")?;
        Ok(hex::encode(Sha256::digest(payload)))
    }

    /// Returns the stable discriminator stored with deduplication state.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match &self.job {
            Job::RunTopologyProbes => "run_topology_probes",
            Job::RegenerateSurface { .. } => "regenerate_surface",
            Job::RebuildDirectory => "rebuild_directory",
            Job::Reindex { .. } => "reindex",
            Job::ResetIndex { .. } => "reset_index",
            Job::RefreshPublicationObject { .. } => "refresh_publication_object",
            Job::DeliverWebhook { .. } => "deliver_webhook",
        }
    }
}

/// An async producer of deferred [`Job`]s.
///
/// A write handler `enqueue`s the propagation work and returns; the consumer
/// (Cloudflare Queues on the Worker, a tokio runner natively) drains and runs
/// it. The [`BackendBounds`] supertrait applies the same target-conditional
/// `Send + Sync` (native) / unbounded (wasm32) bound the rest of the ports use.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait Queue: BackendBounds {
    /// Enqueues one job for asynchronous processing.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying queue cannot accept the message.
    async fn enqueue(&self, job: &Job) -> Result<()>;

    /// Enqueues several jobs. The default sends them one at a time; an impl with
    /// a batch primitive (Cloudflare Queues) may override for fewer round-trips.
    ///
    /// # Errors
    ///
    /// Returns an error if any send fails.
    async fn enqueue_all(&self, jobs: &[Job]) -> Result<()> {
        for job in jobs {
            self.enqueue(job).await?;
        }
        Ok(())
    }
}

/// The native, in-process [`Queue`]: records enqueued jobs in a `Mutex<Vec>`.
///
/// The single-node native hub can drain these on a tokio task; the recorder form
/// is also what the tests assert against. A durable/multi-replica native
/// deployment swaps in a queue-table-backed runner behind the same port.
#[derive(Debug, Default)]
pub struct InMemoryQueue {
    jobs: Mutex<Vec<Job>>,
}

impl InMemoryQueue {
    /// Builds an empty queue.
    #[must_use]
    pub fn new() -> InMemoryQueue {
        InMemoryQueue::default()
    }

    /// Removes and returns all enqueued jobs, in enqueue order (for a drain loop
    /// or a test assertion).
    pub fn drain(&self) -> Vec<Job> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *jobs)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Queue for InMemoryQueue {
    async fn enqueue(&self, job: &Job) -> Result<()> {
        self.jobs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(job.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryQueue, Job, JobEnvelope, Queue};

    #[tokio::test]
    async fn records_jobs_in_order() {
        let q = InMemoryQueue::new();
        q.enqueue(&Job::RegenerateSurface { registry_id: 1 })
            .await
            .unwrap();
        q.enqueue_all(&[Job::RebuildDirectory, Job::Reindex { registry_id: 1 }])
            .await
            .unwrap();
        let drained = q.drain();
        assert_eq!(
            drained,
            vec![
                Job::RegenerateSurface { registry_id: 1 },
                Job::RebuildDirectory,
                Job::Reindex { registry_id: 1 },
            ]
        );
        assert!(q.drain().is_empty(), "drain empties the queue");
    }

    #[test]
    fn job_json_round_trips() {
        let job = Job::Reindex { registry_id: 7 };
        let json = serde_json::to_string(&job).unwrap();
        assert!(json.contains("\"kind\":\"reindex\""));
        let back: Job = serde_json::from_str(&json).unwrap();
        assert_eq!(back, job);

        let reset = Job::ResetIndex { registry_id: 7 };
        let json = serde_json::to_string(&reset).unwrap();
        assert!(json.contains("\"kind\":\"reset_index\""));
        assert_eq!(serde_json::from_str::<Job>(&json).unwrap(), reset);

        let refresh = Job::RefreshPublicationObject {
            registry_id: 7,
            object_key: "images/sha256/abc/disk".into(),
        };
        let json = serde_json::to_string(&refresh).unwrap();
        assert!(json.contains("\"kind\":\"refresh_publication_object\""));
        assert_eq!(serde_json::from_str::<Job>(&json).unwrap(), refresh);

        let delivery = Job::DeliverWebhook {
            delivery_id: "delivery_01HZX".into(),
        };
        let json = serde_json::to_string(&delivery).unwrap();
        assert!(!json.contains("webhook_id") && !json.contains("event\""));
        assert_eq!(serde_json::from_str::<Job>(&json).unwrap(), delivery);
    }

    #[test]
    fn versioned_envelopes_keep_stable_retry_and_continuation_identities() {
        let root = JobEnvelope::new(Job::Reindex { registry_id: 7 });
        root.validate().unwrap();
        let json = serde_json::to_string(&root).unwrap();
        let retried: JobEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(retried.operation_id, root.operation_id);
        assert_eq!(
            retried.payload_digest().unwrap(),
            root.payload_digest().unwrap()
        );

        let first = root
            .continued(Job::Reindex { registry_id: 7 }, "page-2".into())
            .unwrap();
        let duplicate = root
            .continued(Job::Reindex { registry_id: 7 }, "page-2".into())
            .unwrap();
        assert_eq!(first.operation_id, duplicate.operation_id);
        assert_eq!(first.continuation.as_ref().unwrap().sequence, 1);

        let second = first
            .continued(Job::Reindex { registry_id: 7 }, "page-3".into())
            .unwrap();
        assert_ne!(second.operation_id, first.operation_id);
        assert_eq!(second.continuation.as_ref().unwrap().sequence, 2);
    }

    #[test]
    fn legacy_envelopes_are_stable_per_transport_message() {
        let first = JobEnvelope::from_legacy(Job::RebuildDirectory, "transport-message-one");
        let retry = JobEnvelope::from_legacy(Job::RebuildDirectory, "transport-message-one");
        let other = JobEnvelope::from_legacy(Job::RebuildDirectory, "transport-message-two");
        assert_eq!(first.operation_id, retry.operation_id);
        assert_ne!(first.operation_id, other.operation_id);
        first.validate().unwrap();
    }
}
