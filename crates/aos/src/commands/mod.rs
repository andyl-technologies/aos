//! Implementations of the `aos` subcommands.
//!
//! Each module exposes a `run` entry point (some async) that `main.rs`
//! dispatches to after parsing the CLI defined in the `cli` module. Most
//! take an `aos_core::nix::NixRunner` for evaluating/building Nix
//! attributes and an `aos_core::output::Printer` for human/JSON output;
//! the non-Nix commands (`serve`, `token`, `package`, `cache`,
//! `completions`) take only what they need.

pub mod build;
pub mod cache;
pub mod completions;
pub mod describe;
pub mod fmt;
pub mod gc;
pub mod graph;
pub mod hub;
pub(crate) mod hub_auth;
pub mod hub_cutover_verify;
pub mod image;
pub mod lint;
pub mod metadata;
pub mod package;
pub mod prefetch;
pub mod profile;
pub mod repl;
pub mod serve;
pub mod show;
pub mod system;
pub mod test;
pub mod token;
pub mod vm;
pub mod why_depends;
