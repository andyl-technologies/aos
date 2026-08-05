//! Nix evaluator, store, and command-line integration.
//!
//! Store realization and traditional project commands use the classic Nix
//! tools. The optional native seam is eval-only and cannot realize builds:
//!
//! - [`runner`] -- [`NixRunner`], the project-rooted high-level wrapper
//!   used by `aos build`/`aos test` (finds `default.nix`, runs
//!   `nix-build`, `nix-instantiate`, garbage collection, repl).
//! - [`store`] -- [`NixCli`], a thinner per-path wrapper around
//!   `nix-store` queries, realisation, dump/export/import, plus the
//!   [`PathInfo`] metadata record.
//! - [`drv`] -- a hand-rolled parser for `.drv` files (ATerm format)
//!   that extracts fixed-output derivation metadata.
//! - [`env`](mod@env) -- [`aos_nix_env`], the `AOS_ROOT`-derived environment
//!   bindings that point Nix subprocesses at the AOS store layout.
//! - [`native`] -- the in-process RFC-0007 evaluator used for pure on-host
//!   configuration evaluation when the `native-eval` feature is enabled.

pub mod drv;
pub mod env;
#[cfg(feature = "native-eval")]
pub mod native;
pub mod runner;
pub mod store;

pub use env::aos_nix_env;
pub use runner::NixRunner;
pub use store::{NixCli, PathInfo};
