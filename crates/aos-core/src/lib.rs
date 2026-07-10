//! `aos-core` -- Shared foundation library for the `aos` CLI family.
//!
//! This crate collects the pieces that every `aos` binary and helper crate
//! (`aos-cache`, `aos-package`, `aos-server`, ...) needs but that do not
//! belong to any single subcommand:
//!
//! - [`error`] -- the [`AosError`](error::AosError) error type and the
//!   exit-code conventions shared by all `aos` binaries.
//! - [`invocation`] -- argv\[0\]-aware helpers so hint messages echo the
//!   binary name the user actually typed (`aos`, `apm`, or `apr`).
//! - [`nar`] -- NAR (Nix ARchive) handling: narinfo parsing/rendering,
//!   binary-cache layout and signing, the Nix export stream format, and
//!   the AOS upload-pack container.
//! - [`nix`] -- subprocess wrappers around the classic Nix CLI
//!   (`nix-build`, `nix-instantiate`, `nix-store`), `.drv` file parsing,
//!   and the `AOS_ROOT`-relative store environment.
//! - [`output`] -- the [`Printer`](output::Printer) abstraction that
//!   honours `--json`, `--quiet`, and `--verbose` consistently, plus
//!   spinner/progress-bar helpers.
//!
//! The crate is deliberately free of subcommand logic: it provides the
//! plumbing (process spawning, wire formats, terminal output) on top of
//! which the porcelain crates are built.

#![forbid(unsafe_code)]

pub mod error;
pub mod invocation;
pub mod nar;
pub mod nix;
pub mod output;
