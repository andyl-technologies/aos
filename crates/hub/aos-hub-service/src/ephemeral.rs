//! KV-backed short-lived auth artifacts with atomic single-use (RFC-0004 ch.14
//! Phase C6).
//!
//! The login flows mint short-lived, single-use artifacts — OIDC/login state,
//! magic-link tokens, device codes, WebAuthn challenges. They are pure
//! point-key, TTL'd values, so they belong in a [`KvStore`] rather than the
//! relational database: KV expires them natively and serves them sub-ms. The one
//! subtlety is **single use** — a magic link or device code must be redeemable
//! exactly once, even under a double-submit race. [`EphemeralStore::consume`]
//! provides that with the [`Coordinator`]'s atomic `admit(budget = 1)`: the first
//! caller for a key wins the claim and reads the value; a second caller is denied
//! before it can read, so the artifact cannot be redeemed twice.
//!
//! ```text
//! put(ns, id, v, ttl)   ->  KV  {ns}:{id} = v   (expires after ttl)
//! peek(ns, id)          ->  KV  {ns}:{id}        (no claim — for pollable codes)
//! consume(ns, id)       ->  atomic claim, then read+delete (single use)
//! ```
//!
//! `ns` namespaces the artifact (`oidc`, `magic`, `device`, `webauthn`) so keys
//! never collide; `id` is the opaque per-artifact identifier (a token, a code).

use anyhow::Result;

use crate::coordinator::Coordinator;
use crate::kv::KvStore;

/// A KV-backed store for short-lived, optionally single-use auth artifacts.
///
/// Borrows the request's [`KvStore`] and [`Coordinator`]; cheap to construct per
/// use. The store itself is stateless — all state is the KV entries and the
/// coordinator's claim counters.
pub struct EphemeralStore<'a> {
    kv: &'a dyn KvStore,
    coordinator: &'a dyn Coordinator,
}

impl<'a> EphemeralStore<'a> {
    /// Builds a store over a KV store and a coordinator.
    #[must_use]
    pub fn new(kv: &'a dyn KvStore, coordinator: &'a dyn Coordinator) -> EphemeralStore<'a> {
        EphemeralStore { kv, coordinator }
    }

    /// The KV key for `(ns, id)`.
    fn key(ns: &str, id: &str) -> String {
        format!("{ns}:{id}")
    }

    /// Stores `value` under `(ns, id)`, expiring after `ttl_secs` seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if the KV write fails.
    pub async fn put(&self, ns: &str, id: &str, value: &[u8], ttl_secs: i64) -> Result<()> {
        self.kv.put(&Self::key(ns, id), value, Some(ttl_secs)).await
    }

    /// Reads `(ns, id)` **without** claiming it (for a pollable artifact such as
    /// a device code the client polls until approved), or `None` when absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the KV read fails.
    pub async fn peek(&self, ns: &str, id: &str) -> Result<Option<Vec<u8>>> {
        self.kv.get(&Self::key(ns, id)).await
    }

    /// Atomically claims and reads `(ns, id)` **once**, deleting it, or `None`
    /// when it is absent or has already been consumed.
    ///
    /// The single-use guarantee comes from the coordinator's `admit(budget = 1)`:
    /// the first caller wins the claim and gets the value; a concurrent or later
    /// second caller is denied the claim and gets `None`, before it can read — so
    /// the artifact is redeemed exactly once even under a double-submit race.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinator or KV access fails.
    pub async fn consume(&self, ns: &str, id: &str) -> Result<Option<Vec<u8>>> {
        let key = Self::key(ns, id);
        // One claim per artifact: a single fixed window (0) with budget 1.
        if !self
            .coordinator
            .admit("ephemeral_consume", &key, 0, 1)
            .await?
        {
            return Ok(None);
        }
        let value = self.kv.get(&key).await?;
        // Best-effort delete; the TTL is the backstop if it fails.
        let _ = self.kv.delete(&key).await;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::EphemeralStore;
    use crate::coordinator::InMemoryCoordinator;
    use crate::kv::InMemoryKv;

    #[tokio::test]
    async fn put_peek_does_not_consume() {
        let kv = InMemoryKv::new();
        let coord = InMemoryCoordinator::new();
        let store = EphemeralStore::new(&kv, &coord);
        store.put("device", "code1", b"pending", 600).await.unwrap();
        // Peek twice: both see it (no claim).
        assert_eq!(
            store.peek("device", "code1").await.unwrap().as_deref(),
            Some(&b"pending"[..])
        );
        assert_eq!(
            store.peek("device", "code1").await.unwrap().as_deref(),
            Some(&b"pending"[..])
        );
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let kv = InMemoryKv::new();
        let coord = InMemoryCoordinator::new();
        let store = EphemeralStore::new(&kv, &coord);
        store.put("magic", "tok", b"user@acme", 600).await.unwrap();
        // First consume wins.
        assert_eq!(
            store.consume("magic", "tok").await.unwrap().as_deref(),
            Some(&b"user@acme"[..])
        );
        // Second consume is denied (already claimed), and the value is gone.
        assert_eq!(store.consume("magic", "tok").await.unwrap(), None);
        assert_eq!(store.peek("magic", "tok").await.unwrap(), None);
    }

    #[tokio::test]
    async fn consume_absent_is_none() {
        let kv = InMemoryKv::new();
        let coord = InMemoryCoordinator::new();
        let store = EphemeralStore::new(&kv, &coord);
        // Claim succeeds but there is no value to read.
        assert_eq!(store.consume("oidc", "missing").await.unwrap(), None);
    }
}
