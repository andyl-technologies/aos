//! The Worker's Wrangler binding names (wasm32-only).
//!
//! Every request surface — the `aos.hub.v1` RPC methods, the machine-path
//! facade, and the no-JS browse UI + JSON read API — is served by the shared
//! router ([`aos_hub_core::connect::router`]) over
//! [`aos_hub_core::web`], single-sourced with the native hub. There is no
//! schema-init or root-bootstrap endpoint: the schema is migrated and the root
//! admin is created through the seal-authenticated HubDb bootstrap operation.
//!
//! This module only re-exports the binding names ([`bindings`]) the
//! `fetch`/`scheduled` entry points, the README, and `wrangler.toml` agree on.

/// The R2 bucket binding name (`wrangler.toml` `[[r2_buckets]]`).
const R2_BINDING: &str = "REGISTRY_BUCKET";

/// Re-export the binding names so the README/wrangler config and tests agree.
pub mod bindings {
    /// The R2 bucket binding name (`wrangler.toml` `[[r2_buckets]]`).
    pub const R2: &str = super::R2_BINDING;
    /// The KV namespace binding name for sessions (`[[kv_namespaces]]`).
    pub const KV_SESSIONS: &str = "SESSIONS";
    /// The Durable Object binding name for the coordinator (rate-limit/lease/
    /// floor), `[[durable_objects.bindings]]`. RFC-0004 ch.14 Phase B.
    pub const COORDINATOR: &str = "COORDINATOR";
    /// The Cloudflare Queue binding name for deferred post-write jobs
    /// (`[[queues.producers]]`). RFC-0004 ch.14 Phase D.
    pub const QUEUE: &str = "JOBS";
    /// Edge Rate Limiting bindings (`[[ratelimits]]`), one per budget tier
    /// (all `period = 60`). RFC-0004 ch.14 (corrected: edge-local, no DO hop).
    pub const RL_BURST5: &str = "RL_BURST5";
    pub const RL_BURST10: &str = "RL_BURST10";
    pub const RL_BROWSE120: &str = "RL_BROWSE120";
    /// The colocated-SQLite system-of-record Durable Object
    /// (`[[durable_objects.bindings]]`, `new_sqlite_classes` class `HubDb`).
    /// RFC-0004 ch.14 Phase E.
    pub const HUB_DB: &str = "HUB_DB";
}
