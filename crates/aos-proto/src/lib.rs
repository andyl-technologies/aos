//! Generated protobuf and ConnectRPC definitions for the AOS server API.
//!
//! `build.rs` compiles the authoritative `.proto` sources under `src/proto/`
//! once and generates their Rust module tree with `connectrpc-build`. The
//! resulting definitions are pulled in below via [`include!`]. The schema
//! covers these versioned API modules:
//!
//! - `aos::cache::v1` — binary cache operations (cache info, narinfo
//!   lookup, NAR upload/download, pack upload, missing-path queries).
//! - `aos::build::v1` — remote build requests and the streamed
//!   `BuildEvent` log/status messages.
//! - `aos::gc::v1` — garbage-collection requests, eviction candidates,
//!   and GC result summaries.
//! - `aos::auth::v1` — exchanging a provisioning token for a JWT access
//!   token.
//! - `aos::hub::v1` — the Hub's registry and control-plane API:
//!   registries with verified index status, packages, channels with
//!   partition maps, and signed releases. Implemented by
//!   `aos-hub`.
//! - `aos::sandbox::v1` — generic sandbox lifecycle, execution, filesystem
//!   views, snapshots, capabilities, operations, and observations.
//! - `aos::sandbox::coordinator::v1` — compatibility, lease, snapshot-transfer,
//!   and ordered-watch DATA used by local recovery and inventory validation.
//!   Coordinator-only session, exchange and watch carriers and their RPCs
//!   belong to the separately selected `aos-sandbox-coordinator-protocol` crate.
//!
//! Message types are generated `buffa` structs; each selected service also gets
//! a typed ConnectRPC client (e.g. `CacheServiceClient`) and a server trait.
//! The `aos-remote` crate wraps the clients in a
//! higher-level API (`AosClient`), and `aos-server` implements the
//! server side.
//!
//! Shared schemas generate directly from their complete original descriptors.
//! Local semantic, capability, inventory, lease and replay DATA keep their
//! existing module paths, fields, views and JSON support without `multi-node`.
//! The optional transport schema imports these definitions with the unchanged
//! protobuf package and references their original Rust owners directly. This
//! crate neither generates coordinator RPC helpers nor depends back on that
//! optional owner; generic public/local ConnectRPC bindings remain here.
//!
//! To change the API surface, edit the `.proto` files and rebuild; never
//! edit the generated output.
include!(concat!(env!("OUT_DIR"), "/_connectrpc.rs"));

/// Re-exports the protobuf message trait for consumers of generated messages.
pub use prost::Message as ProstMessage;
