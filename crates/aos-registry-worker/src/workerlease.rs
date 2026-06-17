//! The D1-backed [`PublishLease`] for the shared service (wasm32-only).
//!
//! The shared [`RpcService`](aos_registry_core::service::RpcService) serializes a
//! registry's mutable-pointer flips through the [`PublishLease`] port
//! ([`aos_registry_core::lease`]). The native hub holds the lease in process
//! memory, but a Cloudflare Worker request may land in any isolate with its own
//! empty memory, so a process-local lease cannot serialize two publishers that
//! land on different isolates. This module keeps the lease in D1 — the same
//! sqlite database the rest of the Worker drives — so it is shared across every
//! isolate of the deployment.
//!
//! The `publish_leases` table is owned by the shared `MIGRATIONS` (v21), so it
//! is created by the Worker's `_init` schema bootstrap, not lazily here.
//!
//! # Atomicity
//!
//! [`acquire`](PublishLease::acquire) is a single conditional upsert: it takes
//! the lease iff no row exists, the existing row's `deadline` has passed, or the
//! existing row is already held by the same token. The `ON CONFLICT … DO UPDATE
//! … WHERE` predicate makes the take atomic under D1's per-statement execution,
//! so two isolates racing the same registry cannot both win — the loser's update
//! affects zero rows, which it reports as a conflict.

use async_trait::async_trait;

use aos_registry_core::backend::Backend;
use aos_registry_core::lease::{PublishLease, LEASE_TTL_SECS};
use aos_registry_core::value::Value;

use crate::d1backend::D1Backend;

/// A D1-backed [`PublishLease`] shared across worker isolates.
///
/// Built once per request from the bound D1 database; the `publish_leases` table
/// (shared `MIGRATIONS` v21) persists one live lease per registry across isolate
/// invocations.
pub struct D1PublishLease {
    backend: D1Backend,
}

impl D1PublishLease {
    /// Build a lease store over a D1 backend.
    #[must_use]
    pub fn new(backend: D1Backend) -> D1PublishLease {
        D1PublishLease { backend }
    }

    /// The current holder of `registry_id`'s lease, if one is live at `now`.
    async fn live_holder(&self, registry_id: i64, now: i64) -> anyhow::Result<Option<String>> {
        let row = self
            .backend
            .query_opt(
                "SELECT holder_token_id FROM publish_leases \
                 WHERE registry_id = ? AND deadline > ?",
                &[Value::Int(registry_id), Value::Int(now)],
            )
            .await?;
        match row {
            Some(row) => Ok(Some(row.get::<String>(0)?)),
            None => Ok(None),
        }
    }
}

#[async_trait(?Send)]
impl PublishLease for D1PublishLease {
    async fn acquire(&self, registry_id: i64, token_id: &str, now: i64) -> Result<(), String> {
        let deadline = now + LEASE_TTL_SECS;
        // One conditional upsert: insert when no row exists, else update only
        // when the prior lease is expired or already mine. The `WHERE` on the
        // conflict update is what makes a live, foreign lease un-takeable.
        let affected = self
            .backend
            .execute(
                "INSERT INTO publish_leases (registry_id, holder_token_id, deadline) \
                 VALUES (?, ?, ?) \
                 ON CONFLICT(registry_id) DO UPDATE SET \
                   holder_token_id = excluded.holder_token_id, \
                   deadline = excluded.deadline \
                 WHERE publish_leases.deadline <= ? \
                    OR publish_leases.holder_token_id = excluded.holder_token_id",
                &[
                    Value::Int(registry_id),
                    Value::Text(token_id.to_string()),
                    Value::Int(deadline),
                    Value::Int(now),
                ],
            )
            .await;
        match affected {
            Ok(rows) if rows >= 1 => Ok(()),
            Ok(_) => {
                // Zero rows changed: a *different* token holds a live lease.
                // Read the holder for the conflict message; if the read itself
                // fails or the holder vanished in the race, report a generic
                // holder rather than mislabelling it as success.
                match self.live_holder(registry_id, now).await {
                    Ok(Some(holder)) => Err(holder),
                    Ok(None) => Err("unknown".to_string()),
                    Err(err) => {
                        worker::console_error!("publish_leases holder read failed: {err:#}");
                        Err("unknown".to_string())
                    }
                }
            }
            Err(err) => {
                // A transport failure is not a lease conflict. Fail closed by
                // reporting a conflict (the publisher retries); the lease
                // self-expires after LEASE_TTL_SECS so this never deadlocks.
                worker::console_error!("publish_leases acquire failed: {err:#}");
                Err("unavailable".to_string())
            }
        }
    }

    async fn release(&self, registry_id: i64, token_id: &str) {
        // Delete iff still mine, so a late release after a takeover never evicts
        // the new holder. Best-effort: a failure is logged, and the lease
        // self-expires regardless.
        if let Err(err) = self
            .backend
            .execute(
                "DELETE FROM publish_leases WHERE registry_id = ? AND holder_token_id = ?",
                &[Value::Int(registry_id), Value::Text(token_id.to_string())],
            )
            .await
        {
            worker::console_error!("publish_leases release failed: {err:#}");
        }
    }
}
