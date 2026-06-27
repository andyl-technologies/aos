//! Read-through KV caching for hot point-key state (RFC-0004 ch.14 Phase C).
//!
//! Phase C moves the request hot path's point-key lookups — sessions, API
//! tokens, instance config, the host→registry routing table, trust rosters —
//! off the relational `Backend` (which carries D1's ~120 ms per-request session
//! cost) and in front of a [`KvStore`](crate::kv::KvStore). The pattern is
//! **cache-aside / read-through with write-through**: look the key up in KV,
//! and on a miss load it from the database and populate KV with a short TTL, so
//! the next request is served from the edge-cached store.
//!
//! Because the KV store is eventually consistent, every cached value carries a
//! **short TTL** ([`HOT_TTL_SECS`]) so a stale entry self-heals quickly, and
//! mutations explicitly [`invalidate`] the key (delete-on-write) so a change is
//! observed at the next read rather than after the TTL. The two together bound
//! staleness to "until the next read after a write, or `HOT_TTL_SECS`,
//! whichever is first" — the read-your-writes contract the doc accepts for this
//! tier.
//!
//! [`read_through`] is generic over any JSON-serializable value and any async
//! loader, so each call site (`service`, `web`) names its own key namespace
//! (`sess:`, `tok:`, `cfg:`, `fe:`, `roster:`) and value type.

use std::future::Future;

use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};

use crate::kv::KvStore;

/// The default TTL, in seconds, for a hot cached value.
///
/// Short by design: the KV store is eventually consistent, so a brief TTL caps
/// how long a stale entry survives if a delete-on-write invalidation is missed
/// (e.g. a write on another replica). 60 s is the Workers KV minimum and an
/// acceptable revocation/refresh lag for sessions, tokens, config, and routing.
pub const HOT_TTL_SECS: i64 = 60;

/// Reads `key` through `kv`, loading from `load` and writing through on a miss.
///
/// Returns the cached value when present; otherwise awaits `load`, and — when it
/// yields `Some` — serializes it into `kv` under `key` with `ttl_secs` before
/// returning it. A `None` from `load` is **not** cached (absence is cheap to
/// re-check and must not pin a negative result past a create). A corrupt or
/// schema-stale cached entry (one that fails to deserialize into `T`) is treated
/// as a miss and reloaded, so a value-shape change never wedges the cache.
///
/// The write-through is best-effort: a KV write failure is swallowed (the
/// freshly-loaded value is still returned), so a degraded cache never fails a
/// request that the database could serve.
///
/// # Errors
///
/// Returns an error only if the KV **read** or the `load` future errors; a KV
/// **write** failure is swallowed (logged by the store impl), not propagated.
pub async fn read_through<T, F, Fut>(
    kv: &dyn KvStore,
    key: &str,
    ttl_secs: Option<i64>,
    load: F,
) -> Result<Option<T>>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    if let Some(bytes) = kv.get(key).await? {
        // A hit that fails to deserialize (corrupt or an old value shape) falls
        // through to a reload rather than erroring.
        if let Ok(value) = serde_json::from_slice::<T>(&bytes) {
            return Ok(Some(value));
        }
    }
    let loaded = load().await?;
    if let Some(value) = &loaded {
        if let Ok(bytes) = serde_json::to_vec(value) {
            // Best-effort write-through: a degraded cache must not fail a request.
            let _ = kv.put(key, &bytes, ttl_secs).await;
        }
    }
    Ok(loaded)
}

/// Invalidates `key` in `kv` (delete-on-write), so the next read reloads.
///
/// Best-effort: a delete failure is swallowed, since the [`HOT_TTL_SECS`] TTL is
/// the backstop that eventually expires a stale entry even if this misses.
pub async fn invalidate(kv: &dyn KvStore, key: &str) {
    let _ = kv.delete(key).await;
}

#[cfg(test)]
mod tests {
    use super::{invalidate, read_through, HOT_TTL_SECS};
    use crate::kv::{InMemoryKv, KvStore};
    use std::cell::Cell;

    #[tokio::test]
    async fn loads_on_miss_then_serves_from_cache() {
        let kv = InMemoryKv::new();
        let loads = Cell::new(0);
        let load = || async {
            loads.set(loads.get() + 1);
            Ok(Some(42u64))
        };
        // First read: miss → load → write-through.
        let v1: Option<u64> = read_through(&kv, "k", Some(HOT_TTL_SECS), load)
            .await
            .unwrap();
        assert_eq!(v1, Some(42));
        assert_eq!(loads.get(), 1);
        // Second read: hit → loader not called.
        let v2: Option<u64> = read_through(&kv, "k", Some(HOT_TTL_SECS), || async {
            loads.set(loads.get() + 1);
            Ok(Some(99u64))
        })
        .await
        .unwrap();
        assert_eq!(v2, Some(42), "served the cached value, not the new loader");
        assert_eq!(loads.get(), 1, "loader not called on a hit");
    }

    #[tokio::test]
    async fn invalidate_forces_a_reload() {
        let kv = InMemoryKv::new();
        read_through(&kv, "k", Some(HOT_TTL_SECS), || async { Ok(Some(1u64)) })
            .await
            .unwrap();
        invalidate(&kv, "k").await;
        let v: Option<u64> =
            read_through(&kv, "k", Some(HOT_TTL_SECS), || async { Ok(Some(2u64)) })
                .await
                .unwrap();
        assert_eq!(v, Some(2), "reloaded after invalidation");
    }

    #[tokio::test]
    async fn none_is_not_cached() {
        let kv = InMemoryKv::new();
        let v: Option<u64> = read_through(&kv, "absent", Some(HOT_TTL_SECS), || async { Ok(None) })
            .await
            .unwrap();
        assert_eq!(v, None);
        // Nothing was written, so a later create is visible immediately.
        let v2: Option<u64> = read_through(&kv, "absent", Some(HOT_TTL_SECS), || async {
            Ok(Some(7u64))
        })
        .await
        .unwrap();
        assert_eq!(v2, Some(7));
    }

    #[tokio::test]
    async fn corrupt_entry_is_treated_as_miss() {
        let kv = InMemoryKv::new();
        // Write a value that is not valid JSON for the requested type.
        kv.put("k", b"not json", Some(HOT_TTL_SECS)).await.unwrap();
        let v: Option<u64> =
            read_through(&kv, "k", Some(HOT_TTL_SECS), || async { Ok(Some(5u64)) })
                .await
                .unwrap();
        assert_eq!(v, Some(5), "reloaded over the corrupt entry");
    }
}
