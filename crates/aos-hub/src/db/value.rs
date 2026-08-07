//! Engine-neutral value/row marshalling, re-exported from
//! [`aos_hub_core::value`].
//!
//! The types moved to the runtime-agnostic core crate (RFC-0004 Phase 5) so the
//! Cloudflare Worker's HubDb backend can share them; this re-export keeps the
//! hub's `db::value::…` paths stable.

pub use aos_hub_core::value::*;
