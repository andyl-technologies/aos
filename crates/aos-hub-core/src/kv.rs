//! The key-value store port: hot, point-key, read-mostly state off the SQL DB.
//!
//! RFC-0004 chapter 14 moves the request hot path's point-key lookups —
//! sessions, API tokens, instance config, the host→registry routing table, trust
//! rosters, and short-lived auth artifacts — out of the relational `Backend` and
//! onto a key-value store, because each relational lookup carries per-request session
//! cost for a single-key `get` that needs none of the database's transactional
//! model. Cloudflare recommends exactly this for "session data, credentials (API
//! keys), and configuration data."
//!
//! [`KvStore`] is the narrow port both shells implement:
//!
//! - the **Cloudflare Worker** backs it with **Workers KV** (sub-ms hot reads,
//!   edge-cached) — `WorkerKv` in the worker crate over the `SESSIONS` binding;
//! - the **native hub** backs it with an in-process store ([`InMemoryKv`] here,
//!   or a persistent embedded store such as LMDB) — the native process is
//!   single-node so an in-process map is already microsecond-fast.
//!
//! The store is **eventually consistent** by contract (Workers KV propagates a
//! write globally in up to ~60 s), so only data that tolerates that — or carries
//! its own freshness floor (short TTL, write-through, source-on-miss) — belongs
//! here. Strongly-consistent counters/leases use the [`Coordinator`](crate::coordinator)
//! port instead.
//!
//! Keys are opaque UTF-8 strings the caller namespaces (`sess:`, `tok:`,
//! `cfg:`, `fe:`…); values are bytes. A `ttl_secs` of `Some(n)` expires the
//! entry after `n` seconds (the natural fit for sessions/tokens/one-time
//! codes); `None` stores it until overwritten or deleted.
//!
//! The port carries the same target-conditional bound as the rest of the core
//! ports ([`BackendBounds`]): `Send + Sync` natively, unbounded on the
//! single-threaded wasm32 Worker.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Result;

use crate::backend::BackendBounds;
use crate::clock::now_unix_secs;

/// An async key-value store for hot, point-key, eventually-consistent state.
///
/// Implementors map `get`/`put`/`delete` onto their substrate (Workers KV on the
/// Worker, an in-process or embedded store natively). Values are bytes; the
/// string helpers ([`get_str`](KvStore::get_str)/[`put_str`](KvStore::put_str))
/// are provided for the common UTF-8 case.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait KvStore: BackendBounds {
    /// Returns the value stored at `key`, or `None` when absent or expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store cannot be reached.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Stores `value` at `key`, expiring it after `ttl_secs` seconds when set.
    ///
    /// A `ttl_secs` of `None` stores the value until it is overwritten or
    /// deleted. Overwrites any existing value (and resets/clears the TTL).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store cannot be reached, or (Workers
    /// KV) the write exceeds a platform limit.
    async fn put(&self, key: &str, value: &[u8], ttl_secs: Option<i64>) -> Result<()>;

    /// Removes `key`. A no-op when the key is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store cannot be reached.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Returns the UTF-8 value at `key`, or `None` when absent/expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be reached or the stored bytes are
    /// not valid UTF-8.
    async fn get_str(&self, key: &str) -> Result<Option<String>> {
        match self.get(key).await? {
            Some(bytes) => Ok(Some(String::from_utf8(bytes)?)),
            None => Ok(None),
        }
    }

    /// Stores a UTF-8 `value` at `key` with an optional TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store cannot be reached.
    async fn put_str(&self, key: &str, value: &str, ttl_secs: Option<i64>) -> Result<()> {
        self.put(key, value.as_bytes(), ttl_secs).await
    }
}

/// One stored entry: the bytes and an optional absolute expiry (unix seconds).
#[derive(Clone, Debug)]
struct Entry {
    /// The stored value.
    bytes: Vec<u8>,
    /// Unix second after which the entry is expired and treated as absent;
    /// `None` never expires.
    expires_at: Option<i64>,
}

impl Entry {
    /// Whether this entry is expired as of `now` (unix seconds).
    fn expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|deadline| now >= deadline)
    }
}

/// The native, in-process [`KvStore`]: a `Mutex<HashMap>` with lazy TTL eviction.
///
/// Correct and microsecond-fast for the common single-node native hub (the
/// process is one address space, so a map is the in-process analog of the
/// Worker's edge KV). Expired entries are evicted lazily on access. It is **not**
/// shared across processes/replicas and does **not** survive a restart: a
/// multi-replica or restart-durable native deployment swaps in a persistent
/// embedded store (LMDB) behind this same port, exactly as the publish lease
/// swaps [`InMemoryLease`](crate::lease::InMemoryLease) for a shared store.
#[derive(Debug, Default)]
pub struct InMemoryKv {
    entries: Mutex<HashMap<String, Entry>>,
}

impl InMemoryKv {
    /// Builds an empty in-memory store.
    #[must_use]
    pub fn new() -> InMemoryKv {
        InMemoryKv::default()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl KvStore for InMemoryKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let now = now_unix_secs();
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        match entries.get(key) {
            Some(entry) if entry.expired(now) => {
                // Lazily evict the expired entry so it is reported absent and the
                // map does not accumulate dead keys on the read path.
                entries.remove(key);
                Ok(None)
            }
            Some(entry) => Ok(Some(entry.bytes.clone())),
            None => Ok(None),
        }
    }

    async fn put(&self, key: &str, value: &[u8], ttl_secs: Option<i64>) -> Result<()> {
        let expires_at = ttl_secs.map(|ttl| now_unix_secs() + ttl.max(0));
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.insert(
            key.to_string(),
            Entry {
                bytes: value.to_vec(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryKv, KvStore};

    #[tokio::test]
    async fn put_get_delete_round_trip() {
        let kv = InMemoryKv::new();
        assert_eq!(kv.get("sess:a").await.unwrap(), None, "absent key is None");
        kv.put("sess:a", b"hello", None).await.unwrap();
        assert_eq!(
            kv.get("sess:a").await.unwrap().as_deref(),
            Some(&b"hello"[..])
        );
        // Overwrite replaces the value.
        kv.put_str("sess:a", "world", None).await.unwrap();
        assert_eq!(
            kv.get_str("sess:a").await.unwrap().as_deref(),
            Some("world")
        );
        kv.delete("sess:a").await.unwrap();
        assert_eq!(kv.get("sess:a").await.unwrap(), None, "deleted key is None");
    }

    #[tokio::test]
    async fn ttl_zero_expires_immediately() {
        let kv = InMemoryKv::new();
        // A non-positive TTL yields an already-passed deadline (now + 0), so the
        // entry reads back as absent — the lazy-eviction path.
        kv.put("tok:x", b"v", Some(0)).await.unwrap();
        assert_eq!(kv.get("tok:x").await.unwrap(), None, "ttl=0 is expired");
    }

    #[tokio::test]
    async fn ttl_in_future_is_present() {
        let kv = InMemoryKv::new();
        kv.put("tok:y", b"v", Some(3600)).await.unwrap();
        assert!(
            kv.get("tok:y").await.unwrap().is_some(),
            "future TTL is live"
        );
    }
}
