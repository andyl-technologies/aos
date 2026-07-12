//! The AOS build and binary cache server.
//!
//! This crate implements the server side of the AOS package distribution
//! system: a Nix-compatible binary cache combined with a remote build
//! executor, fronted by both a plain HTTP/REST API and ConnectRPC services
//! mounted on the same [axum](https://docs.rs/axum) router.
//!
//! # What the server does
//!
//! - **Binary cache** — serves `nix-cache-info`, `.narinfo` metadata, and
//!   NAR archives (optionally zstd/xz compressed, with byte-range support)
//!   from the local Nix store, scoped per *view*.
//! - **Views** — named slices of the store (`/{view}/...` URL prefix). Each
//!   view owns its own GC root tree (`gcroots/{view}/{bin,src,tmp}`) and
//!   JSON metadata (`meta/{view}/...`), with per-view TTLs, size budgets,
//!   concurrency limits, and anonymous-read policy ([`views`], [`config`]).
//! - **Builds** — clients upload derivation closures (single NARs or batched
//!   packs) and trigger `nix-store --realise`; build progress is streamed
//!   back as Server-Sent Events or ConnectRPC streams with replay support
//!   ([`build`], [`pack`], [`routes`]).
//! - **Auth** — long-lived provisioning tokens (SQLite-backed, [`tokens`])
//!   are exchanged for short-lived HS256 JWTs at `POST /oauth2/token`
//!   ([`auth`]); tokens are administered locally over a Unix socket
//!   ([`bootstrap`]).
//! - **Garbage collection** — TTL expiry, LRU/score-based eviction, and
//!   store GC, exposed via `POST /{view}/gc` and the GC RPC service
//!   ([`evict`], [`gc`]).
//! - **Operations** — narinfo signing ([`sign`], [`narinfo`]), TLS with
//!   self-signed fallback ([`tls`]), and graceful drain/shutdown with build
//!   crash-recovery state ([`drain`]).
//!
//! # Request flow
//!
//! A typical client interaction:
//!
//! 1. Exchange a provisioning secret for a JWT at `POST /oauth2/token`.
//! 2. `POST /{view}/query-missing` to learn which closure paths the server
//!    lacks, then upload them via `PUT /{view}/store/{hash}` or
//!    `POST /{view}/upload-pack`.
//! 3. `POST /{view}/build?drv=...` to realise the derivation, streaming SSE
//!    progress events until a terminal `complete` or `error` event.
//! 4. Fetch outputs back through the cache endpoints
//!    (`GET /{view}/{hash}.narinfo`, `GET /{view}/nar/{filename}`).
//!
//! The HTTP surface is assembled in [`routes::router`]; the equivalent
//! ConnectRPC services live in [`services`].

#![forbid(unsafe_code)]

pub mod access;
pub mod auth;
pub mod bootstrap;
pub mod build;
pub mod compress;
pub mod config;
pub mod drain;
pub mod evict;
pub mod gc;
pub mod memo;
pub mod narinfo;
pub mod pack;
pub mod routes;
pub mod services;
pub mod sign;
pub mod store;
pub mod tls;
pub mod tokens;
pub mod views;

use std::path::PathBuf;

/// Returns the AOS state root directory.
///
/// Defaults to `/var/lib/aos`; override at runtime by setting the
/// `AOS_ROOT` environment variable. All server state — the Nix store
/// database, GC roots, view metadata, partial uploads, and build state
/// files — lives under this directory.
pub fn aos_root() -> PathBuf {
    std::env::var("AOS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/aos"))
}
