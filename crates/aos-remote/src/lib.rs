//! `aos-remote` — a typed client for talking to a remote AOS server.
//!
//! The AOS server (`aos serve`) exposes a ConnectRPC API for its binary
//! cache, remote builds, garbage collection, and token-based auth. This
//! crate wraps the generated service clients from `aos-proto` in a single
//! ergonomic handle, [`AosClient`], that:
//!
//! - validates inputs (URLs, view names, store hashes) before they hit
//!   the wire;
//! - authenticates once (provisioning token -> JWT) and attaches the
//!   bearer token to every subsequent request;
//! - streams NAR uploads/downloads in chunks and surfaces remote build
//!   progress through a [`BuildEvent`] callback.
//!
//! It is consumed by the `aos` CLI for `aos build --remote` and the
//! remote modes of `aos gc` and `aos cache`.
//!
//! Entry points: [`AosClient::connect`] (authenticate with a provisioning
//! token) and [`AosClient::connect_with_token`] (reuse an existing JWT).

#![forbid(unsafe_code)]

/// ConnectRPC-based client for the AOS server.
pub mod client;

pub use client::AosClient;

// Re-export proto types that consumers need.
pub use aos_proto::aos::build::v1::BuildEvent;
pub use aos_proto::aos::gc::v1::{EvictionCandidate, GcResponse};
