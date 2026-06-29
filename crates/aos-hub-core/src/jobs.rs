//! The async job-queue port: deferred post-write propagation (RFC-0004 ch.14
//! Phase D).
//!
//! A write (a publish, a config change) should commit its durable state fast and
//! defer the *expensive propagation* — regenerating the machine surface,
//! rebuilding the global directory projection, invalidating edge-cached read
//! models, delivering webhooks, re-indexing — to an asynchronous worker. That
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

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::backend::BackendBounds;

/// One deferred unit of post-write propagation.
///
/// Enqueued synchronously by a write handler and run asynchronously by the
/// queue consumer. Serializable so it crosses the Cloudflare Queues boundary and
/// is single-sourced between the shells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Job {
    /// Regenerate a registry's machine surface (NAR/narinfo pointers) after a
    /// publish.
    RegenerateSurface {
        /// The registry whose surface to regenerate.
        registry_id: i64,
    },
    /// Rebuild the global registry/cache **directory** projection (the instance
    /// home's cached listing — RFC-0004 ch.14 Phase D, `crate::directory`).
    RebuildDirectory,
    /// Re-index a published registry's surface into D1 (the event-driven
    /// counterpart to the Cron indexer).
    Reindex {
        /// The registry to re-index.
        registry_id: i64,
    },
    /// Invalidate edge-cached read-model keys after the underlying state changed.
    InvalidateReadModel {
        /// The cache keys (or URLs) to purge.
        keys: Vec<String>,
    },
    /// Deliver a webhook event to a configured endpoint.
    DeliverWebhook {
        /// The webhook subscription id.
        webhook_id: i64,
        /// The event name (e.g. `release.published`).
        event: String,
    },
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
    use super::{InMemoryQueue, Job, Queue};

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
        let job = Job::InvalidateReadModel {
            keys: vec!["https://hub/andyl/main/".into()],
        };
        let json = serde_json::to_string(&job).unwrap();
        assert!(json.contains("\"kind\":\"invalidate_read_model\""));
        let back: Job = serde_json::from_str(&json).unwrap();
        assert_eq!(back, job);
    }
}
