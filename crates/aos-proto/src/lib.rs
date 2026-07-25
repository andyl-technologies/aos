//! Generated protobuf and ConnectRPC definitions for the AOS server API.
//!
//! This crate contains no hand-written code: `build.rs` compiles the
//! `.proto` sources under `src/proto/` with `connectrpc-build`, and the
//! resulting Rust module tree is pulled in below via [`include!`]. The
//! schema covers four versioned services, each in its own module:
//!
//! - `aos::cache::v1` — binary cache operations (cache info, narinfo
//!   lookup, NAR upload/download, pack upload, missing-path queries).
//! - `aos::build::v1` — remote build requests and the streamed
//!   `BuildEvent` log/status messages.
//! - `aos::gc::v1` — garbage-collection requests, eviction candidates,
//!   and GC result summaries.
//! - `aos::auth::v1` — exchanging a provisioning token for a JWT access
//!   token.
//! - `aos::registry::v1` — the registry hub's read-path API (RFC-0004):
//!   registries with verified index status, packages, channels with
//!   partition maps, and signed releases. Implemented by
//!   `aos-hub`.
//!
//! Message types are plain `prost` structs; each service additionally
//! gets a typed ConnectRPC client (e.g. `CacheServiceClient`) and a
//! server trait. The `aos-remote` crate wraps the clients in a
//! higher-level API (`AosClient`), and `aos-server` implements the
//! server side.
//!
//! To change the API surface, edit the `.proto` files and rebuild; never
//! edit the generated output. Buffa's generated default-instance witness
//! implementations are isolated in the private `generated` module and pinned
//! by [`safety`]; all hand-written code remains under `deny(unsafe_code)`.

#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_connectrpc.rs"));
}

pub use generated::*;

pub mod safety;
