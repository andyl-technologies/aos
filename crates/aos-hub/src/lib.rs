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
//! 2. **Machines**: a byte-faithful facade over the registry's machine
//!    paths (`HEAD`, `info/refs`, `objects/…`, `channels/…`,
//!    `nix-cache-info`, `*.narinfo`, `nar/…`) with the same
//!    immutable/mutable cache-header split `apr origin upload` writes.
//! 3. **Itself**: a checkpointed indexer that re-walks the surface exactly
//!    as an `apm` client would — loose-object reads, SSH-Ed25519 tag and
//!    commit verification, name binding — and never displays unverified
//!    state.
//!
//! The hub is a *control plane over a static data plane*: the registry
//! surface stays the source of truth, the SQL database holds only
//! registry registration (system of record) plus a rebuildable index.
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
//! - [`console`] — the authenticated producer console: session login, the
//!   account profile, device approval, org/registry management pages, and
//!   the CSRF-checked POST flows.
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
//! - [`compat`] — the machine-path read facade.
//! - [`facade`] — the machine-path write facade: authenticated surface
//!   uploads, the publish lease, and index-after-flip.
//! - [`signing`] — hub-side hosted-key signing: signs release tags and
//!   channel partitions for opt-in registries, writing surface objects the
//!   indexer's own verifier accepts.
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

pub mod auth;
pub mod cloudflare;
pub mod compat;
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
/// The tenancy/IAM domain model, re-exported from [`aos_hub_core::domain`]
/// (RFC-0004 Phase 5) so the Worker shares it; keeps `crate::domain::…` stable.
pub use aos_hub_core::domain;
pub mod export;
pub mod facade;
pub mod fetch;
/// Package/release listing filters, re-exported from
/// [`aos_hub_core::filter`] (RFC-0004 Phase 5); keeps `crate::filter::…` stable.
pub use aos_hub_core::filter;
pub mod gitwrite;
pub mod indexer;
pub mod mirror;
pub mod narlist;
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
