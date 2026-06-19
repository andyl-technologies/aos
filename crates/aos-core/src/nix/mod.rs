//! Wrappers around the classic (non-flake) Nix command-line tools.
//!
//! Everything here shells out to stock Nix binaries -- no experimental
//! features required -- so it works against any Nix installation:
//!
//! - [`runner`] -- [`NixRunner`], the project-rooted high-level wrapper
//!   used by `aos build`/`aos test` (finds `default.nix`, runs
//!   `nix-build`, `nix-instantiate`, garbage collection, repl).
//! - [`store`] -- [`NixCli`], a thinner per-path wrapper around
//!   `nix-store` queries, realisation, dump/export/import, plus the
//!   [`PathInfo`] metadata record.
//! - [`eval`] -- [`NixEval`], the narrow evaluation seam that defaults to
//!   [`NixCli`] and can be implemented by the native `aos-nix` crate.
//! - [`drv`] -- a hand-rolled parser for `.drv` files (ATerm format)
//!   that extracts fixed-output derivation metadata and input edges.
//! - [`diff`] -- `.drv` differential comparison over the [`NixEval`] seam.
//! - [`env`](mod@env) -- [`aos_nix_env`], the `AOS_ROOT`-derived environment
//!   bindings that point Nix subprocesses at the AOS store layout.

pub mod diff;
pub mod drv;
pub mod env;
pub mod eval;
pub mod runner;
pub mod store;

pub use env::{aos_nix_command, aos_nix_env, aos_tokio_nix_command};
pub use eval::{
    DrvClosure, NativeMode, NixEval, NixEvalConfig, native_mode_from_env, select_evaluator,
    select_evaluator_with_config, select_native_diff_candidate_with_config,
};
pub use runner::NixRunner;
pub use store::{NixCli, PathInfo};
