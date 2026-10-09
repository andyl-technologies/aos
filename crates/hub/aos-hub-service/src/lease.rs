//! The publish-lease port: serializing a registry's mutable-pointer flips.
//!
//! A publish pipeline writes immutable objects first (loose git objects, NARs,
//! release packs) and then flips the registry's *mutable pointers* (`HEAD`,
//! `info/refs`, `channels/**`, `nix-cache-info`). If two publishers interleaved
//! their pointer flips for the same registry, a reader could observe a `HEAD`
//! from one publish and an `info/refs` from another. The publish lease prevents
//! that: the first mutable-pointer write of a pipeline takes a per-registry
//! lease keyed by the writing token, and while the lease is held and unexpired a
//! *different* token's mutable-pointer write is rejected. Immutable object
//! writes never take the lease.
//!
//! - [`PublishLease`] — `acquire` (take or refresh, or report the conflicting
//!   holder) / `release` (drop iff mine). The hub serves the facade write path
//!   through this port so the same serialization logic is single-sourced across
//!   the native hub and the Cloudflare Worker.
//!
//! # Deployment mapping
//!
//! - The **native hub** backs the lease with an in-process [`InMemoryLease`] (a
//!   `Mutex<HashMap>`): a single-replica hub serializes pointer flips correctly
//!   and cheaply. (A multi-replica native deployment would need a shared store,
//!   as for the Worker.)
//! - The **Cloudflare Worker** backs the lease with the strongly consistent
//!   coordinator Durable Object. Each request may land in a different isolate,
//!   so a process-local lease cannot serialize pointer flips; the coordinator's
//!   single serialized instance can.
//!
//! The port carries the same target-conditional bound as the rest of the core
//! ports ([`BackendBounds`]): `Send + Sync` natively, unbounded on the
//! single-threaded wasm32 Worker.
//!
//! [`CoordinatorLease`] namespaces
//! its keys under `publish:` and delegates admission and release to the shared
//! [`Coordinator`] port.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::backend::BackendBounds;
use crate::coordinator::Coordinator;

/// Grace period, in seconds, after which an idle publish lease expires and
/// another token may take it.
///
/// A publish pipeline holds the lease only as long as it is actively writing
/// pointers; this bounds how long a crashed or abandoned publisher can block
/// another from flipping the same registry's pointers.
pub const LEASE_TTL_SECS: i64 = 300;

/// Serializes a registry's mutable-pointer flips across concurrent publishers.
///
/// The first mutable-pointer write of a publish pipeline [`acquire`]s the
/// registry's lease on behalf of the writing token; a *different* token's
/// mutable write is rejected while the lease is live, and the pipeline
/// [`release`]s the lease when it is rejected (so a conflicting write does not
/// hold quota or the lease). The invariant: **only the lease holder flips a
/// registry's pointers** for the lease's lifetime.
///
/// [`acquire`]: PublishLease::acquire
/// [`release`]: PublishLease::release
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait PublishLease: BackendBounds {
    /// Acquire or refresh the lease for `registry_id` on behalf of `token_id`,
    /// or report the conflicting holder.
    ///
    /// Returns `Ok(())` when `token_id` already holds the lease (the deadline is
    /// refreshed to `now + `[`LEASE_TTL_SECS`]) or no live lease exists (a new
    /// one is taken). Returns `Err(holder)` with the conflicting token id when a
    /// *different* token holds an unexpired lease.
    ///
    /// `now` is the current unix time in seconds; the caller supplies it so the
    /// clock is testable.
    ///
    /// # Errors
    ///
    /// The `Err` variant is the *conflict* signal carrying the current holder's
    /// token id, not a transport failure: a durable implementation that cannot
    /// reach its store treats that as an internal error of the surrounding write
    /// handler, not a lease conflict, so it returns a holder string only for a
    /// genuine live-lease collision and otherwise propagates the IO error out of
    /// band (by acquiring optimistically — see the Worker impl).
    async fn acquire(&self, registry_id: i64, token_id: &str, now: i64) -> Result<(), String>;

    /// Release the lease for `registry_id` iff `token_id` currently holds it.
    ///
    /// A no-op when the lease is held by another token or already expired/absent,
    /// so a late release after a takeover never clobbers the new holder. Called
    /// when a mutable-pointer write is rejected *after* acquiring (a downstream
    /// quota or write failure), and is best-effort: a failure to release is not
    /// fatal because the lease self-expires after [`LEASE_TTL_SECS`].
    async fn release(&self, registry_id: i64, token_id: &str);
}

/// One registry's in-memory publish lease (holder + deadline).
///
/// Held by the token that first flips a mutable pointer in a publish pipeline;
/// a different token's mutable write is blocked until the deadline passes (see
/// [`LEASE_TTL_SECS`]).
#[derive(Debug, Clone)]
struct LeaseEntry {
    /// The `sub` (token id) of the JWT that holds the lease.
    holder_token_id: String,
    /// Unix time after which the lease is considered abandoned.
    deadline: i64,
}

/// The native, process-local [`PublishLease`]: a `Mutex<HashMap>` of
/// `registry_id -> `lease.
///
/// Correct and cheap for the common single-replica native hub (publish writes
/// are rare and short). It is **not** shared across processes/replicas: a
/// multi-replica deployment must use a shared coordinator-backed lease so two
/// publishers landing on different replicas cannot both acquire. This is the relocated behavior of the hub's prior
/// in-`AppState` `LeaseMap`.
#[derive(Debug, Default)]
pub struct InMemoryLease {
    leases: Mutex<HashMap<i64, LeaseEntry>>,
}

impl InMemoryLease {
    /// Builds an empty in-memory lease map.
    #[must_use]
    pub fn new() -> InMemoryLease {
        InMemoryLease::default()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl PublishLease for InMemoryLease {
    async fn acquire(&self, registry_id: i64, token_id: &str, now: i64) -> Result<(), String> {
        let mut leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        match leases.get(&registry_id) {
            Some(lease) if lease.deadline > now && lease.holder_token_id != token_id => {
                Err(lease.holder_token_id.clone())
            }
            _ => {
                leases.insert(
                    registry_id,
                    LeaseEntry {
                        holder_token_id: token_id.to_string(),
                        deadline: now + LEASE_TTL_SECS,
                    },
                );
                Ok(())
            }
        }
    }

    async fn release(&self, registry_id: i64, token_id: &str) {
        let mut leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        // Drop only iff we still hold it: a late release after a takeover must
        // not evict the new holder.
        if leases
            .get(&registry_id)
            .is_some_and(|lease| lease.holder_token_id == token_id)
        {
            leases.remove(&registry_id);
        }
    }
}

/// A [`PublishLease`] backed by the strongly-consistent [`Coordinator`] port.
///
/// RFC-0004 chapter 14 routes the publish lease through a coordinator and
/// onto the [`Coordinator`]'s generic lease primitive. On the Worker the
/// coordinator is a Durable Object (`WorkerCoordinator`) — a single serialized
/// instance provides cross-isolate exclusion; natively it is the in-process
/// [`InMemoryCoordinator`](crate::coordinator::InMemoryCoordinator). The lease
/// key namespaces the registry id under `publish:` so it does not collide with
/// other coordinator keys.
pub struct CoordinatorLease {
    coordinator: Arc<dyn Coordinator>,
}

impl CoordinatorLease {
    /// Builds a publish lease over a shared [`Coordinator`].
    #[must_use]
    pub fn new(coordinator: Arc<dyn Coordinator>) -> CoordinatorLease {
        CoordinatorLease { coordinator }
    }

    /// The coordinator key for a registry's publish lease.
    fn key(registry_id: i64) -> String {
        format!("publish:{registry_id}")
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl PublishLease for CoordinatorLease {
    async fn acquire(&self, registry_id: i64, token_id: &str, now: i64) -> Result<(), String> {
        match self
            .coordinator
            .acquire_lease(&Self::key(registry_id), token_id, LEASE_TTL_SECS, now)
            .await
        {
            // Acquired or refreshed by us.
            Ok(None) => Ok(()),
            // A different token holds a live lease — the conflict signal.
            Ok(Some(holder)) => Err(holder),
            // A coordinator IO error is not a lease conflict: acquire
            // optimistically so a transient coordinator failure never blocks a
            // legitimate publish (matching the coordinator's out-of-band
            // error handling). The surrounding write handler surfaces real IO
            // failures of the pointer writes themselves.
            Err(_) => Ok(()),
        }
    }

    async fn release(&self, registry_id: i64, token_id: &str) {
        // Best-effort: a failure to release is not fatal (the lease self-expires
        // after `LEASE_TTL_SECS`).
        let _ = self
            .coordinator
            .release_lease(&Self::key(registry_id), token_id)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::InMemoryCoordinator;

    #[tokio::test]
    async fn coordinator_lease_matches_lease_semantics() {
        let lease = CoordinatorLease::new(Arc::new(InMemoryCoordinator::new()));
        // First token takes it; same token refreshes; a different token conflicts.
        assert!(lease.acquire(1, "token-a", 1000).await.is_ok());
        assert!(lease.acquire(1, "token-a", 1010).await.is_ok());
        assert_eq!(
            lease.acquire(1, "token-b", 1020).await,
            Err("token-a".into())
        );
        // A different registry is independent.
        assert!(lease.acquire(2, "token-b", 1020).await.is_ok());
        // The holder's release frees it for the other token.
        lease.release(1, "token-b").await; // no-op (not holder)
        assert_eq!(
            lease.acquire(1, "token-b", 1030).await,
            Err("token-a".into())
        );
        lease.release(1, "token-a").await;
        assert!(lease.acquire(1, "token-b", 1040).await.is_ok());
    }

    #[tokio::test]
    async fn lease_is_held_by_first_token_until_expiry() {
        let leases = InMemoryLease::new();
        // First token takes the lease.
        assert!(leases.acquire(1, "token-a", 1000).await.is_ok());
        // Same token refreshes it.
        assert!(leases.acquire(1, "token-a", 1010).await.is_ok());
        // A different token is blocked while the lease is live.
        assert_eq!(
            leases.acquire(1, "token-b", 1020).await,
            Err("token-a".into())
        );
        // A different registry is independent.
        assert!(leases.acquire(2, "token-b", 1020).await.is_ok());
        // After the last refresh's deadline passes, the other token may take it
        // (the refresh at t=1010 set the deadline to 1010 + TTL).
        assert!(leases
            .acquire(1, "token-b", 1010 + LEASE_TTL_SECS + 1)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn release_only_drops_the_holder_s_lease() {
        let leases = InMemoryLease::new();
        assert!(leases.acquire(1, "token-a", 1000).await.is_ok());
        // A non-holder's release is a no-op: token-a still holds it.
        leases.release(1, "token-b").await;
        assert_eq!(
            leases.acquire(1, "token-b", 1010).await,
            Err("token-a".into())
        );
        // The holder's release frees it; token-b can now take it.
        leases.release(1, "token-a").await;
        assert!(leases.acquire(1, "token-b", 1020).await.is_ok());
    }
}
