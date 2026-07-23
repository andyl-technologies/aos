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
//! the `aos-core`-facing `native` handle. Unsafe code remains denied by default;
//! the serial force path has one explicitly allowed, invariant-documented
//! stable-arena dereference used to avoid per-force ownership promotion.

#![deny(unsafe_code)]
// The tree-walk evaluator threads source-span context through many internal
// helpers, so several constructors take more positional arguments than the
// default clippy threshold. `TreeWalkError` itself now boxes its payload (see
// `eval::tree_walk::errors`), so `Result<Value, TreeWalkError>` is one pointer
// wide and `result_large_err` no longer applies.
#![allow(clippy::too_many_arguments)]

// Re-exports so the moved modules' paths to lower crates keep resolving.
pub use aos_nix_syntax as syntax;
pub use ratchet_core as compile;
pub use ratchet_value::{attrs, hashcons, heap, list, value};

pub mod cache;
pub mod eval;
pub mod runtime;
pub mod string;
