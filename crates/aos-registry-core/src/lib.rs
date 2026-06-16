//! Runtime-agnostic core of the AOS registry hub (RFC-0004 Phase 5).
//!
//! This crate holds the pieces that are independent of how the hub is
//! deployed, so a single implementation can serve both the native
//! `aos-registry-hub` binary and the Cloudflare Worker:
//!
//! - [`value`] — the engine-neutral [`Value`](value::Value)/[`Row`](value::Row)
//!   marshalling types and the [`ToValue`](value::ToValue) binding trait.
//!
//! Later phases move the SQL dialect translation, the async `Backend` trait,
//! the indexer, and the HTTP handlers here too, leaving the deployment crates
//! as thin shells around their concrete backend (sqlx for native, D1 for the
//! Worker).
//!
//! The crate carries no I/O, runtime, or driver dependencies of its own and
//! compiles to `wasm32-unknown-unknown`.

pub mod value;
