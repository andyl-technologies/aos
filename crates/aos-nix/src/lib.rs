//! `aos-nix` -- the native RFC-0007 Nix evaluator.
//!
//! This crate owns the in-process evaluator described by RFC-0007. The
//! long-term shape is a safe tree-walk oracle plus progressively faster
//! execution tiers, all validating against C++ Nix through the
//! `aos_core::nix::NixEval` seam. At the start of Phase 1 this crate is
//! intentionally a default-off shim: it exposes [`NixNative`] with the same
//! public boundary the real evaluator will use, but every evaluation request
//! returns [`NativeEvalError::Unsupported`] so callers can fall back to
//! `aos_core::nix::NixCli`.
//!
//! # Module Map
//!
//! - [`error`] defines the typed native-evaluation failure taxonomy used by the
//!   fallback layer.
//! - [`native`] exposes [`NixNative`], the `aos-core`-facing evaluator handle.
//! - [`syntax`] owns the byte-oriented frontend: lexer first, then arena AST and
//!   parser as Phase 1 grows.
//! - [`compile`] owns the frontend passes that turn parsed syntax into the
//!   scope-resolved IR consumed by later evaluator tiers.
//! - [`cache`] owns content-addressed frontend cache keys and on-disk entry
//!   layout.
//! - [`value`] owns the 16-byte tagged runtime value word used by the safe
//!   tree-walk oracle.
//! - [`heap`] owns the Phase-1 one-shot bump arena used for evaluator heap
//!   objects.
//!
//! Future Phase-1 modules land below this boundary in the order specified by
//! the RFC: `attrs`, `eval`, `runtime`, and `store`.

#![forbid(unsafe_code)]

pub mod cache;
pub mod compile;
pub mod error;
pub mod heap;
pub mod native;
pub mod syntax;
pub mod value;

pub use error::{NativeEvalError, SrcSpan};
pub use native::NixNative;
