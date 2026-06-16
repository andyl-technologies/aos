//! Arguments for `aos package` (a.k.a. `apm`) — the package manager.
//!
//! `PackageArgs` wraps the `PackageCommand` subcommand tree defined in
//! the `aos-package` crate (install, remove, registry operations, ...)
//! and adds the global `--dry-run` and `--yes` flags. Invoking the
//! binary as `apm` or `apr` routes here implicitly (see the multicall
//! dispatch in `main.rs`).
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::package`, which delegates to `aos_package::run`.

use clap::Args;

// Re-export command enums from the package library crate so clap can use them.
pub use aos_package::PackageCommand;

#[derive(Args)]
#[command(after_long_help = aos_package::ENVIRONMENT_HELP)]
pub struct PackageArgs {
    #[command(subcommand)]
    pub command: PackageCommand,

    /// Show what would be done without doing it
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Assume yes to all prompts
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,
}
