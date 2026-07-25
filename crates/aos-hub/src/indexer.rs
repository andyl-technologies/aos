//! Fetch → verify → load → index orchestration (re-export shim).
//!
//! The canonical indexer was relocated to [`aos_hub_core::indexer`]
//! (RFC-0004 Phase 5) so the native hub's reindex and the Cloudflare Worker's
//! Cron job run the *same* indexing logic over the
//! [`SurfaceFetch`](aos_hub_core::fetch::SurfaceFetch) port. This module
//! re-exports it unchanged so every existing `crate::indexer::…` caller — the
//! facade reindex via [`HubReindexer`](crate::coreports::HubReindexer), the CLI
//! index command, the seeding path, the mirror verifier, validation, and the
//! test suite — compiles against the relocated definitions without edits.
//!
//! See [`aos_hub_core::indexer`] for the module overview: the failure
//! classification of [`index_and_record`], the full-walk [`index_registry`], the
//! incremental fast path, the per-release pack probe, and the anti-rollback
//! floor logic.

pub use aos_hub_core::indexer::*;
