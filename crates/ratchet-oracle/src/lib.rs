//! `ratchet-oracle` -- the reference tree-walk evaluator for RFC-0007.
//!
//! This crate owns the strongly-connected oracle cluster carved out of the
//! `aos-nix` monolith in RFC-0007 §1.1 Phase 1b: the safe tree-walk evaluator
//! ([`eval`]), the runtime builtin execution layer ([`runtime`]), the
//! incremental frontend cache ([`cache`]), and byte-oriented Nix strings with
//! their string contexts ([`string`]). These modules mutually depend and form
//! the safe reference implementation that faster execution tiers validate
//! against. Nix store-format helpers live in `aos-nix-compat`.
//!
//! The crate sits above the value and frontend crates (`ratchet-value`,
//! `ratchet-core`, `aos-nix-syntax`) and below the `aos-nix` umbrella, which
//! re-exports these modules and adds the typed error taxonomy, diagnostics, and
//! the `aos-core`-facing `native` handle.

#![forbid(unsafe_code)]
// The tree-walk evaluator intentionally threads rich `TreeWalkError` values
// and source-span context through many internal helpers. Refactoring that API
// shape is a separate design pass, not a mechanical clippy cleanup.
#![allow(clippy::result_large_err, clippy::too_many_arguments)]

// Re-exports so the moved modules' paths to lower crates keep resolving.
pub use aos_nix_syntax as syntax;
pub use ratchet_core as compile;
pub use ratchet_value::{attrs, hashcons, heap, list, value};

pub mod cache;
pub mod eval;
pub mod runtime;
pub mod string;
