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
//! - [`attrs`] owns the Phase-1 flat immutable attribute-set representation.
//! - [`eval`] owns the safe tree-walk oracle and its thunk-forcing state.
//! - [`list`] owns the Phase-1 immutable list-spine representation.
//! - [`string`] owns byte-oriented Nix strings and string contexts.
//! - [`runtime`] owns shared runtime metadata such as builtin declarations.
//!
//! The Phase-1 value ABI is intentionally host-portable only across the
//! RFC-supported matrix: 64-bit x86-64 or AArch64 hosts on Linux or Darwin.
//! Host architecture affects evaluator speed only; the configured Nix
//! `system` value determines evaluation output.
//!
//! Future Phase-1 modules land below this boundary in the order specified by
//! the RFC: `store`.

#![forbid(unsafe_code)]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("aos-nix requires a 64-bit host pointer width");

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("aos-nix supports only x86-64 and AArch64 host architectures");

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("aos-nix supports only Linux and Darwin host operating systems");

pub mod attrs;
pub mod cache;
pub mod compile;
pub mod diagnostic;
mod drv_materialize;
pub mod error;
pub mod eval;
pub mod heap;
pub mod list;
pub mod native;
pub mod runtime;
pub mod string;
pub use aos_nix_syntax as syntax;
pub mod value;

pub use error::{NativeCliFallbackReason, NativeEvalError, SrcSpan};
pub use native::{NativeDrvClosure, NixNative};
