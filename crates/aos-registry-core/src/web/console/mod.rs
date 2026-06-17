//! The shared producer console (RFC-0004 Phase 5, console-dedup stage B/C).
//!
//! The console's request handlers are transport- and runtime-neutral `axum`
//! handlers that run on the shared [`Database`](crate::db::Database) and reach
//! every platform-specific capability through a *port* (see [`ports`]), so the
//! native hub and the Cloudflare Worker mount the same console router. This
//! module owns the [`ports::ConsoleDeps`] bundle today; the ported handlers and
//! their `console_router` land here as the handler move proceeds in
//! rate-limit-survivable chunks.

pub mod ports;

pub use ports::{AdvanceOutcome, ChannelAdvancer, ConsoleDeps, HttpClient};
