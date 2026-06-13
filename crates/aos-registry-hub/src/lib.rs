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
//! - [`domain`] — tenancy/IAM domain model: orgs, projects, principals,
//!   and the pure role/permission/scope authorization kernel.
//! - [`auth`] — authentication: provisioning tokens, JWTs, human sessions,
//!   device-code and magic-link flows, and the axum extractors that gate
//!   requests.
//! - [`indexer`] — fetch → verify → load → index orchestration.
//! - [`validation`] — presence-depth cache consistency validation.
//! - [`compat`] — the machine-path facade.
//! - [`rpc`] — the `aos.registry.v1` ConnectRPC read-path services.
//! - [`ui`] — server-rendered HTML pages.
//! - [`server`] — axum router assembly tying the above together.

pub mod auth;
pub mod compat;
pub mod db;
pub mod domain;
pub mod fetch;
pub mod indexer;
pub mod rpc;
pub mod server;
pub mod surface;
pub mod ui;
pub mod validation;
