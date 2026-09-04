//! AOS registry hub: a management WebUI and read index for AOS registries.
//!
//! This crate implements the phase-1 surface of RFC-0004
//! (`docs/rfcs/0004-registry-hub.md`): a server that *indexes* one or more
//! AOS registries — the SHA-256 git surfaces published as static files by
//! `apr` — and serves three audiences from one URL space:
//!
//! 1. **Humans**: server-rendered browse pages (registry home, packages,
//!    channels, releases) under the reserved `/-/` namespace, in the
//!    no-JS "release-engineering paper" design language.
//! 2. **Machines**: byte-faithful registry and cache delivery through explicit
//!    topology endpoints and routes. Registries, caches, placements, storage
//!    bindings, and URLs remain independent resources rather than being
//!    inferred from a slug.
//! 3. **Itself**: a checkpointed indexer that re-walks the surface exactly
//!    as an `apm` client would — loose-object reads, SSH-Ed25519 tag and
//!    commit verification, name binding — and never displays unverified
//!    state.
//!
//! The hub is a control plane over a static data plane: signed registry
//! releases remain the source of truth, while SQL records logical resources,
//! physical placement, delivery topology, retained control, and rebuildable
//! indexes.
//!
//! # Module map
//!
//! - [`surface`] — pure-Rust reader for the registry wire surface: loose
//!   git objects, commits/trees/tags, SSHSIG verification, refs.
//! - [`fetch`] — the [`fetch::SurfaceFetch`] transport trait with
//!   filesystem (`file://`) and HTTP(S) implementations.
//! - [`db`] — sqlite-backed storage: the `registries` system-of-record
//!   table and the rebuildable index tables.
//! - [`config`] — the SQL-backed configuration change-set engine: drafts,
//!   semantic diffs, atomic apply, and snapshot-targeted forward revert
//!   over the append-only audit/changeset/revision tables.
//! - [`console`] — shared browser-session, login, account-security, invitation,
//!   and device-approval ceremonies. Resource management is the hermetic
//!   Leptos client over the canonical Connect API.
//! - [`domain`] — tenancy/IAM domain model: orgs, projects, principals,
//!   and the pure role/permission/scope authorization kernel.
//! - [`export`] — org backup/export: a portable JSON bundle of the SQL system
//!   of record (secrets redacted) plus copyable registry surfaces.
//! - [`auth`] — authentication: provisioning tokens, JWTs, human sessions,
//!   device-code, magic-link, and per-org OIDC SSO flows, and the axum
//!   extractors that gate requests.
//! - [`indexer`] — fetch → verify → load → index orchestration.
//! - [`mirror`] — registry mirroring: full-mirror sync (verify-then-copy the
//!   upstream surface into the local binding) and the pull-through fetch-on-miss
//!   cache.
//! - [`stack`] — the nestable try/mirror cache-stack expression and its
//!   committed TOML encoding.
//! - [`ratelimit`] — in-memory per-endpoint fixed-window rate limiting for the
//!   pre-auth surfaces (device-authorization, magic-link issuance, token
//!   exchange, anonymous browse/search).
//! - [`validation`] — presence- and integrity-depth cache consistency
//!   validation, stack-aware coverage, and repair planning.
//! - [`aos_hub_core::surface_write`] — typed publication writes, leases, and
//!   index-after-commit coordination.
//! - [`signing`] — pure release-tag and channel-partition signing primitives;
//!   custody and consumer bindings are governed by retained control.
//! - [`gitwrite`] — git-backed configuration change requests: writes a
//!   draft-signed commit editing a committed file to
//!   `refs/hub/changes/<change_id>` for a maintainer to review and promote.
//! - [`rpc`] — the `aos.hub.v1` ConnectRPC read-path services plus the
//!   tenancy and webhook write-path services.
//! - [`seed`] — dev seed: populates a fresh hub with a browsable, signed demo
//!   registry, a demo org/user/password, and a sample publish token.
//! - [`webhook`] — outbound webhooks: the [`webhook::WebhookEvent`] taxonomy,
//!   HMAC-signed delivery, and the background delivery worker.
//! - [`ui`] — server-rendered HTML pages.
//! - [`server`] — axum router assembly tying the above together (including the
//!   `/healthz` and Prometheus `/metrics` observability endpoints).

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("the aos-hub test-support feature must never be enabled in a release build");

pub mod auth;
pub mod cloudflare;
/// Config change-set staging/revert, re-exported from
/// [`aos_hub_core::config`] (RFC-0004 Phase 5); keeps `crate::config::…` stable.
pub use aos_hub_core::config;
/// The crawl-policy value type, re-exported from [`aos_hub_core::crawl`]; keeps
/// `crate::crawl::…` stable for the CLI.
pub use aos_hub_core::crawl;
/// Native adapters from the hub's concrete types to the shared service ports
/// ([`aos_hub_core::ratelimit::RateLimiter`],
/// [`aos_hub_core::fetch::SurfaceProvider`]); RFC-0004 Phase 5.
pub mod coreports;
pub mod db;
pub mod egress_gateway;
/// The tenancy/IAM domain model, re-exported from [`aos_hub_core::domain`]
/// (RFC-0004 Phase 5) so the Worker shares it; keeps `crate::domain::…` stable.
pub use aos_hub_core::domain;
pub mod export;
pub mod fetch;
pub mod image_snapshot;
/// Package/release listing filters, re-exported from
/// [`aos_hub_core::filter`] (RFC-0004 Phase 5); keeps `crate::filter::…` stable.
pub use aos_hub_core::filter;
pub mod gitwrite;
pub mod indexer;
mod local_fs_delete;
pub mod mirror;
pub mod narlist;
pub mod native_tls;
pub mod probe;
pub mod ratelimit;
pub mod seed;
pub mod server;
pub mod signing;
/// The cache-stack node model, re-exported from [`aos_hub_core::stack`]
/// (RFC-0004 Phase 5) so the Worker shares it; keeps `crate::stack::…` stable.
pub use aos_hub_core::stack;
pub mod surface;
pub mod ui;
pub mod validation;
pub mod webhook;
