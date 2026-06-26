//! `crucible-api` owns the versioned programmatic API surface.
//!
//! Spec index: RFC-0010 files 21.
//!
//! This L4 crate will define the session lifecycle, stepping, query, and
//! temporal-graph API types described by RFC-0010 file 21. It is a
//! safe boundary over versioned data and dispatch shapes.
//!
//! Module map: [`rpc_abi`] owns the versioned RPC boundary constants and frozen
//! golden vectors. Later modules will split by lifecycle, query, and
//! temporal-graph surfaces as those APIs land.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod rpc_abi;

pub use rpc_abi::{
    GOLDEN_RPC_VECTORS, GOLDEN_VECTOR_RPC_PROTOCOL_VERSION, GOLDEN_VECTOR_RPC_REGENERATION_RULE,
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_BUILD, RPC_PROTOCOL_MAJOR,
    RPC_PROTOCOL_MINOR, RPC_PROTOCOL_PATCH, RPC_PROTOCOL_VERSION, RpcAbiError, RpcAttachMode,
    RpcEventClass, RpcGoldenVector, RpcGoldenVectorMessage, RpcStatusCode, encode_rpc_message,
    negotiate_rpc_protocol,
};
