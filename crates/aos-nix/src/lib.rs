//! `aos-nix` -- the native RFC-0007 Nix evaluator.
//!
//! This crate owns the in-process evaluator described by RFC-0007. The
//! implementation is a safe tree-walk evaluator with persistent,
//! dependency-traced early-cutoff caching and an optional JIT tier. It is the
//! production on-host configuration evaluator behind the
//! `aos_core::nix::NixEval` seam. Native errors are typed and fail closed; the
//! production configuration path never falls back to the host or C++ Nix.
//! Differential checks retain the hermetic AOS-built C++ evaluator solely as
//! a byte-parity oracle.
//!
//! # Module Map
//!
//! - [`error`] defines the typed native-evaluation failure taxonomy used by
//!   callers and activation diagnostics.
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
//! - [`jit`] owns safe integration adapters between oracle runtime metadata and
//!   JIT preflights.
//! - [`drv_materialize`] re-exports Nix store-format materialization from
//!   `aos-nix-compat`.
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

pub use aos_nix_compat::drv_materialize;
pub use ratchet_core as compile;
pub use ratchet_oracle::cache;
pub use ratchet_value::attrs;
pub mod diagnostic;
pub mod error;
pub use ratchet_oracle::eval;
pub use ratchet_value::heap;
pub use ratchet_value::list;
pub mod jit;
pub mod native;
pub mod option_graph;
pub mod totality;
pub use aos_nix_syntax as syntax;
pub use ratchet_oracle::runtime;
pub use ratchet_oracle::string;
pub use ratchet_value::value;

pub use error::{
    NativeCliFallbackReason, NativeConflictDef, NativeEvalError, NativeMissingOption,
    NativeMissingOptionKind, NativeResourceLimit, SrcSpan,
};
pub use native::{NativeDrvClosure, NixNative};
pub use option_graph::{NativeEvalOutput, OptionAccess, OptionAccessKind, OptionGraph};
