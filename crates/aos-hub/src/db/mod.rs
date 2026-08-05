//! The hub database layer, re-exported from [`aos_hub_core::db`].
//!
//! The [`Database`] handle — the schema `MIGRATIONS` and every read/write query
//! method, written once over the [`Backend`](crate::db::backend::Backend) trait
//! — moved to the runtime-agnostic core crate (RFC-0004 Phase 5) so the
//! Cloudflare Worker runs the *same* implementation over HubDb SQLite. This
//! re-export keeps the hub's `db::…` paths (and `db::{backend,dialect,value}`)
//! stable; the native `sqlx` constructors ([`Database::open`],
//! [`Database::connect`]) are inherent methods on the re-exported type.

pub use aos_hub_core::db::*;

pub mod backend;
pub mod dialect;
pub mod value;
