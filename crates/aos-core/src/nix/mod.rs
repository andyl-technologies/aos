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
//! - [`drv`] -- a hand-rolled parser for `.drv` files (ATerm format)
//!   that extracts fixed-output derivation metadata.
//! - [`env`](mod@env) -- [`aos_nix_env`], the `AOS_ROOT`-derived environment
//!   bindings that point Nix subprocesses at the AOS store layout.
pub mod drv;
pub mod env;
pub mod runner;
pub mod store;

pub use env::aos_nix_env;
pub use runner::NixRunner;
pub use store::{NixCli, PathInfo};
