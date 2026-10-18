//! Process integration for Nix builds, derivations, and immutable stores.
//!
//! The classic build and store operations invoke Nix without requiring flakes.
//! Authenticated store accessors explicitly enable modern `nix-command`
//! operations when logical store identities cannot be read as host paths.
//! Callers choose project roots, store routing, and executable admission:
//!
//!
//! - [`runner`] -- [`NixRunner`], the project-rooted high-level wrapper
//!   used by `aos build`/`aos test` (finds `default.nix`, runs
//!   `nix-build`, `nix-instantiate`, garbage collection, repl) and the
//!   [`CheckReport`] of a Nix `--check` repeat-build pass.
//! - [`store`] -- [`NixCli`], a thinner per-path wrapper around
//!   `nix-store` queries, realisation, dump/export/import, plus the
//!   [`PathInfo`] metadata record.
//! - [`identity`] -- bounded streaming NAR identities for admitted store tools.
//! - [`error`] -- typed process/discovery failures without CLI exit policy.
//! - [`executable`] -- checked executable paths inside immutable store roots.
//! - [`drv`] -- a hand-rolled parser for `.drv` files (ATerm format)
//!   that extracts fixed-output derivation metadata.
//! - [`env`](mod@env) -- [`aos_nix_env`] and [`configure_aos_nix_store`],
//!   which point Nix subprocesses at the selected AOS store.
pub mod drv;
pub mod env;
pub mod error;
pub mod executable;
pub mod identity;
pub mod runner;
pub mod store;

pub use env::{aos_management_nix_env, aos_nix_env, configure_aos_nix_store};
pub use runner::{CheckFailure, CheckReport, NixRunner};
pub use store::{NixCli, PathInfo};
