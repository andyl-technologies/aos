//! The Cloudflare Queues implementation of the shared [`Queue`] port
//! (wasm32-only).
//!
//! RFC-0004 chapter 14 Phase D defers post-write propagation (surface
//! regeneration, the directory projection rebuild, read-model invalidation,
//! webhook delivery, re-indexing) to an asynchronous queue so the synchronous
//! write stays fast. This is the Worker's producer side: [`WorkerQueue`]
//! implements [`aos_hub_core::jobs::Queue`] over a bound Cloudflare Queue,
//! wrapping each [`Job`](aos_hub_core::jobs::Job) in a versioned, replay-safe
//! [`JobEnvelope`](aos_hub_core::jobs::JobEnvelope) message body. The
//! consumer is an `#[event(queue)]` handler (added with the deploy config); the
//! native hub drains the same [`Job`]s on a tokio runner behind the same port.

use anyhow::anyhow;
use async_trait::async_trait;

use aos_hub_core::jobs::{Job, JobEnvelope, Queue};

/// A [`Queue`] backed by a bound Cloudflare Queue.
///
/// Built per request from `env.queue(binding)`; cheap to construct (it wraps the
/// JS binding handle). Each [`Job`] is sent in a JSON envelope the consumer
/// validates before execution.
pub struct WorkerQueue {
    queue: worker::Queue,
}

impl WorkerQueue {
    /// Wraps a bound Cloudflare Queue producer handle.
    #[must_use]
    pub fn new(queue: worker::Queue) -> WorkerQueue {
        WorkerQueue { queue }
    }

    /// Builds the producer from the Worker environment's queue binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the named queue binding is absent.
    pub fn from_env(env: &worker::Env) -> worker::Result<WorkerQueue> {
        Ok(WorkerQueue::new(
            env.queue(crate::handlers::bindings::QUEUE)?,
        ))
    }

    /// Enqueues already-versioned envelopes without replacing their identities.
    ///
    /// Maintenance fan-out uses this after deriving deterministic child
    /// identities from its dispatcher, making retry after a successful batch
    /// send harmless.
    ///
    /// # Errors
    ///
    /// Returns an error if any Cloudflare batch cannot be accepted.
    pub async fn enqueue_envelopes(&self, envelopes: &[JobEnvelope]) -> anyhow::Result<()> {
        for chunk in envelopes.chunks(100) {
            self.queue
                .send_batch(chunk.iter().cloned())
                .await
                .map_err(|err| anyhow!("queue send_batch: {err}"))?;
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl Queue for WorkerQueue {
    async fn enqueue(&self, job: &Job) -> anyhow::Result<()> {
        // The envelope keeps one operation identity stable across Cloudflare's
        // at-least-once deliveries.
        self.queue
            .send(JobEnvelope::new(job.clone()))
            .await
            .map_err(|err| anyhow!("queue send: {err}"))
    }

    async fn enqueue_all(&self, jobs: &[Job]) -> anyhow::Result<()> {
        // Use the batch primitive for fewer round-trips when there is more than
        // one job (`send_batch` takes an iterator of serializable messages).
        if jobs.is_empty() {
            return Ok(());
        }
        for chunk in jobs.chunks(100) {
            let envelopes = chunk
                .iter()
                .cloned()
                .map(JobEnvelope::new)
                .collect::<Vec<_>>();
            self.enqueue_envelopes(&envelopes).await?;
        }
        Ok(())
    }
}
