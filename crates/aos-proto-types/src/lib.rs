//! Wasm-clean message structs for the `aos.registry.v1` registry-hub API.
//!
//! RFC-0004 Phase 5 unifies the native registry hub and the Cloudflare Worker
//! on one shared `axum` router. Because the `connectrpc` server runtime cannot
//! target `wasm32-unknown-unknown` (it pulls `hyper`/`tokio`/`zstd-sys`), the
//! hub serves a single **Connect-JSON** transport — plain JSON over HTTP
//! (`POST /aos.registry.v1.{Service}/{Method}`) — as ordinary `axum` handlers
//! on both targets. This crate holds the request/response **message types** for
//! that surface, generated from the `.proto` (owned by `aos-proto`) with
//! `prost-build` + `serde` derives and **nothing else**: no `connectrpc`, no
//! `buffa`, no `hyper`/`tokio`. That keeps it wasm-clean, so the worker, the
//! native hub (`aos-hub-core`'s shared handlers), and the `aos-remote`
//! Connect-JSON client all share one set of types.
//!
//! # Wire format
//!
//! The structs serialize as the Connect-JSON request/response bodies. Field
//! names follow the generated (snake_case) Rust names; both ends of the wire
//! are first-party (`aos-remote` ↔ the hub), so this is the agreed shape
//! rather than canonical proto3-JSON. The `prost` binary codec the derives also
//! provide is unused on the wire.
//!
//! ```text
//! POST /aos.registry.v1.RegistryService/GetRegistry
//! Content-Type: application/json
//! { "slug": "acme/cdn" }
//!   -> 200 { "registry": { "slug": "acme/cdn", "name": "…", … } }
//!   -> 4xx { "code": "not_found", "message": "no such registry" }
//! ```
//!
//! The generated module mirrors the proto package path: the
//! `aos.registry.v1` messages are re-exported at the crate root.

#![allow(clippy::all)]

/// The generated `aos.registry.v1` message structs.
///
/// `prost-build` emits one file per proto package; this is the
/// `aos.registry.v1` package. The contents are re-exported at the crate root
/// (see the [`pub use`] below) so consumers write `aos_proto_types::Registry`.
pub mod registry_v1 {
    include!(concat!(env!("OUT_DIR"), "/aos.registry.v1.rs"));
}

pub use registry_v1::*;
