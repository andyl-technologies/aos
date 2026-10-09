//! Generated protobuf and ConnectRPC definitions for AOS build services.
//!
//! This crate contains no hand-written code: `build.rs` compiles the
//! canonical `.proto` sources under `api/proto/` with `connectrpc-build`, and the
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
//!
//! Hub messages are generated independently by `aos-hub-api`.
//!
//! Message types are generated `buffa` structs; each service additionally
//! gets a typed ConnectRPC client (e.g. `CacheServiceClient`) and a
//! server trait. The `aos-build-client` crate wraps the clients in a
//! higher-level API (`AosClient`), and `aos-build-server` implements the
//! server side.
//!
//! To change the API surface, edit the `.proto` files and rebuild; never
//! edit the generated output.
include!(concat!(env!("OUT_DIR"), "/_connectrpc.rs"));
