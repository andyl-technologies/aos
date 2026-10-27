//! Generated Sandbox protobuf messages and ConnectRPC service definitions.
//!
//! The canonical schemas live under `api/proto/aos/sandbox/`. The build script
//! validates their compatibility fixtures and complete shared coordinator
//! descriptor before generating the original Rust namespaces:
//!
//! - `aos::sandbox::v1` owns the public lifecycle, execution, filesystem,
//!   snapshot, capability, discovery, operator, and operation APIs.
//! - `aos::sandbox::local::v1` owns local broker and guest-agent APIs.
//! - `aos::sandbox::coordinator::v1` owns shared compatibility, lease,
//!   snapshot-transfer, and ordered-watch DATA used by local recovery.
//!
//! Shared schemas generate directly from their complete original descriptors.
//! Their messages, enums, borrowed views, and JSON support remain available
//! without `multi-node`. Coordinator-only session, exchange, and watch carriers
//! and RPCs belong to the separately selected coordinator-protocol crate, which
//! references these shared types directly. This crate does not generate that
//! transport or depend on its owner.
//!
//! Build, cache, authentication, and GC service APIs belong to `aos-build-api`;
//! Hub messages belong to `aos-hub-api`. To change a Sandbox schema, edit its
//! canonical `.proto` source and rebuild rather than editing generated output.

include!(concat!(env!("OUT_DIR"), "/_connectrpc.rs"));

/// Re-exports the protobuf message trait for consumers of generated messages.
pub use prost::Message as ProstMessage;
