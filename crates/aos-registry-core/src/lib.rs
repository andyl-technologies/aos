//! Runtime-agnostic core of the AOS registry hub (RFC-0004 Phase 5).
//!
//! This crate holds the pieces that are independent of how the hub is
//! deployed, so a single implementation can serve both the native
//! `aos-registry-hub` binary and the Cloudflare Worker:
//!
//! - [`value`] — the engine-neutral [`Value`](value::Value)/[`Row`](value::Row)
//!   marshalling types and the [`ToValue`](value::ToValue) binding trait.
//! - [`dialect`] — per-engine SQL translation ([`Dialect`](dialect::Dialect)):
//!   placeholder rewriting, DDL type mapping, and the mysql upsert rewrite, so
//!   one source statement form serves sqlite, postgres, and mysql.
//! - [`backend`] — the async [`Backend`](backend::Backend) trait, the
//!   [`Statement`](backend::Statement) unit of atomic work, and the
//!   `split_statements`/`with_returning_id`/`prepare` helpers every driver
//!   reuses. The concrete drivers (`SqlxBackend` for native, D1 for the
//!   Worker) live in the deployment crates and implement this trait.
//!
//! Later phases move the indexer and the HTTP handlers here too, leaving the
//! deployment crates as thin shells around their concrete backend (sqlx for
//! native, D1 for the Worker).
//!
//! The crate carries no I/O, runtime, or driver dependencies of its own and
//! compiles to `wasm32-unknown-unknown`.

pub mod backend;
pub mod dialect;
pub mod value;
