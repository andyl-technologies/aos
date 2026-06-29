//! The coordination port: strongly-consistent counters, leases, and floors.
//!
//! RFC-0004 chapter 14 routes the hub's *atomic* state — fixed-window rate
//! limits, the publish lease, and channel anti-rollback floors — off D1 and onto
//! a primitive that gives **strict serializability** without a per-request SQL
//! round-trip. Workers KV is the wrong tool (eventually consistent, ~1 write/sec
//! per key, no atomic increment); the right one is a **Durable Object**:
//!
//! - the **Cloudflare Worker** backs [`Coordinator`] with a Durable Object whose
//!   single-threaded, single-instance execution serializes every operation
//!   (`WorkerCoordinator` in the worker crate);
//! - the **native hub** backs it with an in-process [`InMemoryCoordinator`] (a
//!   `Mutex`-guarded map) — a single-node process already serializes, and a
//!   restart-durable/multi-replica deployment swaps in an embedded transactional
//!   store (LMDB) behind the same port.
//!
//! The three primitives:
//!
//! - [`admit`](Coordinator::admit) — a fixed-window rate-limit counter: record
//!   one attempt against a window budget, atomically, returning whether it was
//!   admitted. Replaces the D1 `rate_limits` upsert that ran a *write* on every
//!   browse request (RFC-0004 ch.14 "no writes on read paths").
//! - [`acquire_lease`](Coordinator::acquire_lease) /
//!   [`release_lease`](Coordinator::release_lease) — a generic holder/deadline
//!   lease (the publish lease, keyed by registry).
//! - [`advance_floor`](Coordinator::advance_floor) — a monotonic compare-and-set
//!   (a channel's anti-rollback floor): store `value` only if it strictly
//!   exceeds the current floor.
//!
//! The port carries the same target-conditional bound as the rest of the core
//! ports ([`BackendBounds`]): `Send + Sync` natively, unbounded on the
//! single-threaded wasm32 Worker.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Result;

use crate::backend::BackendBounds;

/// A strongly-consistent coordination primitive: atomic counters, leases, floors.
///
/// Every method is serializable with respect to concurrent callers for the same
/// key — the contract the Durable Object impl provides by construction (one
/// instance, single-threaded) and the native in-process impl provides with a
/// `Mutex`. Callers pass `now` (unix seconds) where a clock is needed so the
/// logic stays testable.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait Coordinator: BackendBounds {
    /// Atomically records one attempt in the fixed `window` for `(class, key)`
    /// and returns whether it was admitted (count stayed `< budget`).
    ///
    /// The first attempt in a window admits at count 1; later attempts admit and
    /// increment only while the count is below `budget`; once at budget, further
    /// attempts are denied **without** consuming budget. Two callers racing the
    /// same key cannot both admit at the boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinator cannot be reached. Callers fail open
    /// (admit) on error, mirroring the prior D1 limiter.
    async fn admit(&self, class: &str, key: &str, window: i64, budget: i64) -> Result<bool>;

    /// Acquires or refreshes the lease at `key` for `holder`, or reports the
    /// conflicting holder.
    ///
    /// Returns `Ok(None)` when `holder` already holds the lease (its deadline is
    /// refreshed to `now + ttl_secs`) or no live lease exists (a new one is
    /// taken). Returns `Ok(Some(other))` with the current holder when a
    /// *different* holder's lease is unexpired.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinator cannot be reached (distinct from the
    /// `Ok(Some(_))` conflict signal).
    async fn acquire_lease(
        &self,
        key: &str,
        holder: &str,
        ttl_secs: i64,
        now: i64,
    ) -> Result<Option<String>>;

    /// Releases the lease at `key` iff `holder` currently holds it (else a no-op).
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinator cannot be reached.
    async fn release_lease(&self, key: &str, holder: &str) -> Result<()>;

    /// Monotonic compare-and-set: stores `value` at `key` iff it **strictly
    /// exceeds** the current floor, returning whether it was accepted.
    ///
    /// A value equal to or below the current floor is rejected (`Ok(false)`) and
    /// the floor is unchanged — the anti-rollback guarantee for channel advances.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinator cannot be reached.
    async fn advance_floor(&self, key: &str, value: i64) -> Result<bool>;
}

/// A live lease: holder and the unix-second deadline after which it is abandoned.
#[derive(Clone, Debug)]
struct Lease {
    /// The current holder's opaque id.
    holder: String,
    /// Unix second after which the lease is considered free.
    deadline: i64,
}

/// The native, in-process [`Coordinator`]: `Mutex`-guarded maps for counts,
/// leases, and floors.
///
/// Serializes every operation within one process, which is correct for the
/// single-node native hub. State is non-durable (lost on restart) and
/// process-local (not shared across replicas); a durable/multi-replica native
/// deployment swaps in an embedded transactional store (LMDB) behind this port,
/// exactly as the Worker uses a Durable Object.
#[derive(Debug, Default)]
pub struct InMemoryCoordinator {
    /// Fixed-window counters keyed by `(class, key, window)`.
    counts: Mutex<HashMap<(String, String, i64), i64>>,
    /// Leases keyed by an opaque lease key.
    leases: Mutex<HashMap<String, Lease>>,
    /// Monotonic floors keyed by an opaque floor key.
    floors: Mutex<HashMap<String, i64>>,
}

impl InMemoryCoordinator {
    /// Builds an empty coordinator.
    #[must_use]
    pub fn new() -> InMemoryCoordinator {
        InMemoryCoordinator::default()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Coordinator for InMemoryCoordinator {
    async fn admit(&self, class: &str, key: &str, window: i64, budget: i64) -> Result<bool> {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let slot = counts
            .entry((class.to_string(), key.to_string(), window))
            .or_insert(0);
        if *slot < budget {
            *slot += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn acquire_lease(
        &self,
        key: &str,
        holder: &str,
        ttl_secs: i64,
        now: i64,
    ) -> Result<Option<String>> {
        let mut leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        match leases.get(key) {
            Some(lease) if lease.deadline > now && lease.holder != holder => {
                Ok(Some(lease.holder.clone()))
            }
            _ => {
                leases.insert(
                    key.to_string(),
                    Lease {
                        holder: holder.to_string(),
                        deadline: now + ttl_secs,
                    },
                );
                Ok(None)
            }
        }
    }

    async fn release_lease(&self, key: &str, holder: &str) -> Result<()> {
        let mut leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        if leases.get(key).is_some_and(|lease| lease.holder == holder) {
            leases.remove(key);
        }
        Ok(())
    }

    async fn advance_floor(&self, key: &str, value: i64) -> Result<bool> {
        let mut floors = self.floors.lock().unwrap_or_else(|p| p.into_inner());
        match floors.get(key) {
            Some(&current) if value <= current => Ok(false),
            _ => {
                floors.insert(key.to_string(), value);
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Coordinator, InMemoryCoordinator};

    #[tokio::test]
    async fn admit_enforces_window_budget() {
        let c = InMemoryCoordinator::new();
        // Budget 2 in window 100: two admits, then denied; a denied attempt does
        // not consume further budget, and the next window starts fresh.
        assert!(c.admit("browse", "ip", 100, 2).await.unwrap());
        assert!(c.admit("browse", "ip", 100, 2).await.unwrap());
        assert!(!c.admit("browse", "ip", 100, 2).await.unwrap());
        assert!(!c.admit("browse", "ip", 100, 2).await.unwrap());
        assert!(c.admit("browse", "ip", 101, 2).await.unwrap(), "new window");
        // A different key is independent.
        assert!(c.admit("browse", "ip2", 100, 2).await.unwrap());
    }

    #[tokio::test]
    async fn lease_held_by_first_holder_until_expiry() {
        let c = InMemoryCoordinator::new();
        assert_eq!(
            c.acquire_lease("reg:1", "a", 300, 1000).await.unwrap(),
            None
        );
        // Same holder refreshes.
        assert_eq!(
            c.acquire_lease("reg:1", "a", 300, 1010).await.unwrap(),
            None
        );
        // Different holder blocked while live.
        assert_eq!(
            c.acquire_lease("reg:1", "b", 300, 1020).await.unwrap(),
            Some("a".to_string())
        );
        // After the refresh deadline (1010 + 300) passes, b may take it.
        assert_eq!(
            c.acquire_lease("reg:1", "b", 300, 1311).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn release_only_drops_the_holders_lease() {
        let c = InMemoryCoordinator::new();
        c.acquire_lease("reg:1", "a", 300, 1000).await.unwrap();
        c.release_lease("reg:1", "b").await.unwrap(); // no-op
        assert_eq!(
            c.acquire_lease("reg:1", "b", 300, 1010).await.unwrap(),
            Some("a".to_string())
        );
        c.release_lease("reg:1", "a").await.unwrap();
        assert_eq!(
            c.acquire_lease("reg:1", "b", 300, 1020).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn floor_advances_only_upward() {
        let c = InMemoryCoordinator::new();
        assert!(c.advance_floor("chan:1", 5).await.unwrap(), "first set");
        assert!(
            c.advance_floor("chan:1", 9).await.unwrap(),
            "strictly higher"
        );
        assert!(
            !c.advance_floor("chan:1", 9).await.unwrap(),
            "equal rejected"
        );
        assert!(
            !c.advance_floor("chan:1", 3).await.unwrap(),
            "lower rejected"
        );
        // A different key is independent.
        assert!(c.advance_floor("chan:2", 1).await.unwrap());
    }
}
