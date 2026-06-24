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
//!   [`PathInfo`] metadata record and [`NixInstantiateStats`] capture.
//! - [`eval`] -- [`NixEval`], the narrow evaluation seam that defaults to
//!   [`NixCli`] and can be implemented by the native `aos-nix` crate.
//! - `aos-nix-compat` owns `.drv` ATerm parsing and store-format helpers.
//! - `aos-nix-harness` owns `.drv` differential comparison over the
//!   [`NixEval`] seam.
//! - [`env`](mod@env) -- [`aos_nix_env`], the `AOS_ROOT`-derived environment
//!   bindings that point Nix subprocesses at the AOS store layout.

pub mod env;
pub mod eval;
pub mod runner;
pub mod store;

pub use env::{aos_nix_command, aos_nix_env, aos_tokio_nix_command};
pub use eval::{
    DrvClosure, NativeEvalStats, NativeFallbackStats, NativeMode, NativeShadowStats,
    NativeSuccessStats, NativeVerifyStats, NixEval, NixEvalConfig, NixEvalMode, native_eval_stats,
    native_fallback_stats, native_mode_from_env, native_shadow_stats, native_success_stats,
    native_verify_stats, select_evaluator, select_evaluator_with_config,
    select_native_diff_candidate_with_config,
};
pub use runner::NixRunner;
pub use store::{NixCli, NixInstantiateStats, PathInfo};
