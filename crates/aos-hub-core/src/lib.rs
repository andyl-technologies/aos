//! Runtime-agnostic core of the AOS registry hub (RFC-0004 Phase 5).
//!
//! This crate holds the pieces that are independent of how the hub is
//! deployed, so a single implementation can serve both the native
//! `aos-hub` binary and the Cloudflare Worker:
//!
//! - [`value`] — the engine-neutral [`Value`](value::Value)/[`Row`](value::Row)
//!   marshalling types and the [`ToValue`](value::ToValue) binding trait.
//! - [`dialect`] — per-engine SQL translation ([`Dialect`](dialect::Dialect)):
//!   placeholder rewriting, DDL type mapping, and the mysql upsert rewrite, so
//!   one source statement form serves sqlite, postgres, and mysql.
//! - [`domain`] — the tenancy/IAM model (org → project → registry tree,
//!   principals, and the pure role/permission/scope authorization kernel).
//! - [`email`] — pure transactional-email rendering ([`EmailContent`](email::EmailContent)
//!   plus the magic-link and org-invite renderers), shared so the native hub and
//!   the Worker send byte-identical messages over their different transports.
//! - [`auth`] — runtime-agnostic authentication primitives (Argon2id password
//!   hashing, the token/session/magic/device secret generators, and the
//!   permission-string parser; OIDC, sealing, and WebAuthn to follow).
//! - [`stack`] — the committed `[caches]` cache-stack node model
//!   ([`StackNode`](stack::StackNode)) that round-trips losslessly through JSON;
//!   re-exported from `aos-registry-surface` so the wasm-clean indexer and the
//!   `apm`/`apr` client share one flattener.
//! - [`binding`] — storage-binding kinds ([`BindingKind`](binding::BindingKind))
//!   and the per-runtime capability model ([`RuntimeKind`](binding::RuntimeKind))
//!   that gates which kinds the serving runtime accepts.
//! - [`url_guard`] — the pure SSRF guards (global-IP predicate, network-origin
//!   URL check, HTTP surface-path validator, traversal-safe path join) shared
//!   by the native hub's `fetch` hardening and the Worker's egress policy.
//! - [`backend`] — the async [`Backend`](backend::Backend) trait, the
//!   [`Statement`](backend::Statement) unit of atomic work, the
//!   `split_statements`/`with_returning_id`/`prepare` helpers, and the native
//!   [`SqlxBackend`](backend::SqlxBackend) driver (compiled only off-wasm; the
//!   Worker supplies a D1 `Backend` instead).
//! - [`db`] — the [`Database`](db::Database) handle: the schema `MIGRATIONS`
//!   and every read/write query method, written once over the [`Backend`](backend::Backend)
//!   trait so the native hub and the Worker share one implementation.
//! - [`indexer`] — the canonical fetch → verify → load → index orchestration,
//!   pure logic over the [`SurfaceFetch`](fetch::SurfaceFetch) read port and the
//!   [`Database`](db::Database) write side, so the native hub's reindex and the
//!   Worker's Cron job run byte-identical indexing.
//! - [`placement_read`] — deterministic multi-placement read planning, exact
//!   inventory/current-publication eligibility, and pre-stream failover shared
//!   by both serving runtimes.
//!
//! Later phases move the remaining HTTP handlers here too, leaving the
//! deployment crates as thin shells around their concrete backend (sqlx for
//! native, D1 for the Worker).
//!
//! The crate is **wasm-clean on `wasm32-unknown-unknown`**: native-only pieces
//! (the `sqlx` driver, the secret-key filesystem loader) are gated off that
//! target, and randomness reaches `crypto.getRandomValues` through getrandom's
//! JS backend.

pub mod auth;
pub mod backend;
pub mod binding;
pub mod binding_provision;
pub mod cache;
pub mod cache_scan;
pub mod clock;
pub mod config;
pub mod connect;
pub mod coordinator;
pub mod crawl;
pub mod db;
pub mod dialect;
pub mod directory;
pub mod domain;
pub mod email;
pub mod ephemeral;
pub mod fetch;
pub mod filter;
pub mod gc;
pub mod git;
pub mod gitwrite;
pub mod indexer;
pub mod jobs;
pub mod keymap;
pub mod kv;
pub mod lease;
pub mod migrate;
pub mod nix_sign;
pub mod placement_read;
pub mod ratelimit;
pub mod reindex;
pub mod robots;
pub mod s3surface;
pub mod service;
pub mod signing;
pub mod sigv4;
/// Re-export of the cache-stack node model from `aos-registry-surface`.
///
/// The model lives in the shared wasm-clean surface crate so the `apm`/`apr`
/// client can flatten a `[caches]` stack without depending on `aos-hub-core`;
/// this alias keeps existing `crate::stack::…` paths compiling.
pub use aos_registry_surface::stack;
pub mod surface_write;
pub mod url_guard;
pub mod value;
pub mod web;
pub mod webhook;
