//! The Worker's Wrangler binding names (wasm32-only).
//!
//! Every request surface — the `aos.registry.v1` RPC methods, the machine-path
//! facade, and the no-JS browse UI + JSON read API — is served by the shared
//! router ([`aos_registry_core::connect::router`]) over
//! [`aos_registry_core::web`], single-sourced with the native hub. There is no
//! schema-init or root-bootstrap endpoint: the schema is migrated and the root
//! admin is created by the authenticated operator's CLI over D1
//! (`aos-registry-hub init --target d1:<name>`), never over HTTP.
//!
//! This module only re-exports the binding names ([`bindings`]) the
//! `fetch`/`scheduled` entry points, the README, and `wrangler.toml` agree on.

/// The D1 database binding name (`wrangler.toml` `[[d1_databases]]`).
const D1_BINDING: &str = "REGISTRY_DB";
/// The R2 bucket binding name (`wrangler.toml` `[[r2_buckets]]`).
const R2_BINDING: &str = "REGISTRY_BUCKET";

/// Re-export the binding names so the README/wrangler config and tests agree.
pub mod bindings {
    /// The D1 database binding name (`wrangler.toml` `[[d1_databases]]`).
    pub const D1: &str = super::D1_BINDING;
    /// The R2 bucket binding name (`wrangler.toml` `[[r2_buckets]]`).
    pub const R2: &str = super::R2_BINDING;
    /// The KV namespace binding name for sessions (`[[kv_namespaces]]`).
    pub const KV_SESSIONS: &str = "SESSIONS";
}
