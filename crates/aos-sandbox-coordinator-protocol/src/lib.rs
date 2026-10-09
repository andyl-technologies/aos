//! Generated coordinator/node transport DATA and dormant ConnectRPC bindings.
//!
//! The original authenticated-session, exchange and ordered-watch wire owners
//! live in `aos::sandbox::coordinator::v1`. Their shared protocol, semantic and
//! watch fields use the existing generated types in `aos-proto` directly.
//! The application selects this crate only through its off-default `multi-node`
//! dependency; no listener, handler, worker or authority producer is installed.
//!
//! `build.rs` generates the one transport schema with the unchanged package,
//! field tags, JSON/view support and RPC signatures. Shared local history,
//! capabilities, inventories, leases and snapshot recovery remain below this
//! owner in `aos-proto`. There are no shared-type forwarding reexports here.
include!(concat!(env!("OUT_DIR"), "/_connectrpc.rs"));
