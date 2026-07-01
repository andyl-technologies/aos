//! The Cloudflare Queues implementation of the shared [`Queue`] port
//! (wasm32-only).
//!
//! RFC-0004 chapter 14 Phase D defers post-write propagation (surface
//! regeneration, the directory projection rebuild, read-model invalidation,
//! webhook delivery, re-indexing) to an asynchronous queue so the synchronous
//! write stays fast. This is the Worker's producer side: [`WorkerQueue`]
//! implements [`aos_hub_core::jobs::Queue`] over a bound Cloudflare Queue,
//! serializing each [`Job`](aos_hub_core::jobs::Job) as the message body. The
//! consumer is an `#[event(queue)]` handler (added with the deploy config); the
//! native hub drains the same [`Job`]s on a tokio runner behind the same port.

use anyhow::anyhow;
use async_trait::async_trait;

use aos_hub_core::jobs::{Job, Queue};

/// A [`Queue`] backed by a bound Cloudflare Queue.
///
/// Built per request from `env.queue(binding)`; cheap to construct (it wraps the
/// JS binding handle). Each [`Job`] is sent as a JSON message the consumer
/// decodes back into a `Job`.
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
}

#[async_trait(?Send)]
impl Queue for WorkerQueue {
    async fn enqueue(&self, job: &Job) -> anyhow::Result<()> {
        // Cloudflare Queues serializes the message body; `Job` is `Serialize`.
        // An owned value is sent so `SendMessage::from(T)` infers `T = Job`.
        self.queue
            .send(job.clone())
            .await
            .map_err(|err| anyhow!("queue send: {err}"))
    }

    async fn enqueue_all(&self, jobs: &[Job]) -> anyhow::Result<()> {
        // Use the batch primitive for fewer round-trips when there is more than
        // one job (`send_batch` takes an iterator of serializable messages).
        if jobs.is_empty() {
            return Ok(());
        }
        self.queue
            .send_batch(jobs.iter().cloned())
            .await
            .map_err(|err| anyhow!("queue send_batch: {err}"))
    }
}
