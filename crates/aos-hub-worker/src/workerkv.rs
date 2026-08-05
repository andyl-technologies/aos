//! The Workers KV implementation of the shared [`KvStore`] port (wasm32-only).
//!
//! RFC-0004 chapter 14 moves the request hot path's point-key state — sessions,
//! API tokens, instance config, the host→registry routing table, trust rosters —
//! in **Workers KV**, whose hot reads are edge-cached. This is the Worker's
//! [`KvStore`](aos_hub_core::kv::KvStore) impl over a bound KV namespace (the
//! `SESSIONS` binding, see [`crate::handlers::bindings`]); the native hub
//! supplies an in-process [`InMemoryKv`](aos_hub_core::kv::InMemoryKv) (or a
//! persistent embedded store) behind the same port.
//!
//! # Eventual consistency and TTL
//!
//! Workers KV is eventually consistent (a write propagates globally in up to
//! ~60 s) and enforces a **minimum 60-second TTL**, so a positive `ttl_secs`
//! below 60 is raised to 60. Only data that tolerates that lag belongs here;
//! strongly-consistent counters/leases use the Durable Object
//! [`Coordinator`](aos_hub_core::coordinator::Coordinator) instead.

use anyhow::anyhow;
use async_trait::async_trait;

use aos_hub_core::kv::KvStore;

/// Workers KV's minimum accepted expiration TTL, in seconds.
///
/// The platform rejects an `expiration_ttl` below 60; a caller's shorter
/// positive TTL is raised to this floor so a one-time code still expires
/// promptly without the write being rejected.
const KV_MIN_TTL_SECS: i64 = 60;

/// A [`KvStore`] backed by a bound Workers KV namespace.
///
/// Constructed per request from `env.kv(binding)`; cheap to build (it wraps the
/// JS binding handle). Values are stored and read as raw bytes
/// (`put_bytes`/`get(...).bytes()`), so the port's byte contract is exact.
pub struct WorkerKv {
    kv: worker::kv::KvStore,
}

impl WorkerKv {
    /// Wraps a bound Workers KV namespace handle.
    #[must_use]
    pub fn new(kv: worker::kv::KvStore) -> WorkerKv {
        WorkerKv { kv }
    }
}

#[async_trait(?Send)]
impl KvStore for WorkerKv {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.kv
            .get(key)
            .bytes()
            .await
            .map_err(|err| anyhow!("KV get {key}: {err}"))
    }

    async fn put(&self, key: &str, value: &[u8], ttl_secs: Option<i64>) -> anyhow::Result<()> {
        let mut builder = self
            .kv
            .put_bytes(key, value)
            .map_err(|err| anyhow!("KV put {key}: {err}"))?;
        if let Some(ttl) = ttl_secs {
            // Workers KV requires a TTL >= 60s; raise a shorter positive TTL to
            // the floor. A non-positive TTL is treated as "no expiry" (the caller
            // should `delete` to expire immediately).
            if ttl > 0 {
                builder = builder.expiration_ttl(ttl.max(KV_MIN_TTL_SECS) as u64);
            }
        }
        builder
            .execute()
            .await
            .map_err(|err| anyhow!("KV put {key}: {err}"))
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.kv
            .delete(key)
            .await
            .map_err(|err| anyhow!("KV delete {key}: {err}"))
    }
}
