//! The worker-local `GET /_init` D1 schema setup (wasm32-only).
//!
//! Every request surface — the `aos.registry.v1` RPC methods, the machine-path
//! facade, and the no-JS browse UI + JSON read API — is served by the shared
//! router ([`aos_registry_core::connect::router`]) over
//! [`aos_registry_core::web`], single-sourced with the native hub. The only
//! path that stays worker-local is the one-shot schema bootstrap:
//!
//! ```text
//! /_init   apply the shared D1 schema (one-shot, optional)
//! ```
//!
//! This module also re-exports the Wrangler binding names ([`bindings`]) the
//! `fetch`/`scheduled` entry points, the README, and `wrangler.toml` agree on.

use worker::{Env, Response, Result};

/// Binding names the Worker expects in `wrangler.toml`.
const D1_BINDING: &str = "REGISTRY_DB";
const R2_BINDING: &str = "REGISTRY_BUCKET";

/// Apply the canonical D1 schema (a one-shot operational convenience).
///
/// This is the production schema-setup path: request `GET /_init` once after
/// `wrangler deploy` (there is no separate `wrangler d1 migrations` step — a
/// hand-maintained migration file would diverge from core's `MIGRATIONS`).
///
/// It runs the **shared** schema: constructing
/// [`aos_registry_core::db::Database`] over the [`D1Backend`](crate::d1backend::D1Backend)
/// applies the exact `MIGRATIONS` the native hub uses (RFC-0004 Phase 5 — the
/// Worker and the native hub share one `Database`), rather than a Worker-local
/// read-only schema subset.
///
/// # Errors
///
/// Returns an error if the D1 binding is missing or applying the migrations
/// fails.
pub async fn init_schema(env: &Env) -> Result<Response> {
    use aos_registry_core::db::Database;

    let db_handle = env.d1(D1_BINDING)?;
    Database::with_backend(Box::new(crate::d1backend::D1Backend::new(db_handle)))
        .await
        .map_err(|err| worker::Error::RustError(format!("applying D1 migrations: {err:#}")))?;
    Response::ok("schema applied")
}

/// Re-export the binding names so the README/wrangler config and tests agree.
pub mod bindings {
    /// The D1 database binding name (`wrangler.toml` `[[d1_databases]]`).
    pub const D1: &str = super::D1_BINDING;
    /// The R2 bucket binding name (`wrangler.toml` `[[r2_buckets]]`).
    pub const R2: &str = super::R2_BINDING;
    /// The KV namespace binding name for sessions (`[[kv_namespaces]]`).
    pub const KV_SESSIONS: &str = "SESSIONS";
}
