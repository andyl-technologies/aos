//! The [`Registry`] row the Cron indexer projects from D1.
//!
//! A pure serde struct — no `worker` types — so it compiles and tests on
//! native. The browse UI and JSON read API that once read the richer row/detail
//! models now live in the shared [`aos_registry_core::web`] (rendered from the
//! `aos.registry.v1` read shapes), so only the indexer's registry projection
//! remains here: [`crate::indexer`] selects the public registries it re-walks
//! into this shape.

use serde::{Deserialize, Serialize};

/// One registry's identity and read-relevant configuration.
///
/// Projected from `core::Database` `registries` rows by [`crate::indexer`].
/// `trust_keys` is the raw JSON-array string as stored
/// (`["name:Ed25519:b64", …]`); the indexer parses it for signature
/// verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    /// The registry's row id.
    pub id: i64,
    /// The URL-path slug.
    pub slug: String,
    /// The upstream surface URL (`https://…` or `file://…`).
    pub source_url: String,
    /// JSON array of trust-anchor key lines, as stored.
    pub trust_keys: String,
    /// Whether the indexer fails closed on an unsigned surface (`0`/`1`).
    pub require_signatures: i64,
    /// `public` | `internal` | `private` (this Worker serves only `public`).
    pub visibility: String,
    /// The registry's R2 key prefix within the hub bucket.
    pub prefix: String,
}
