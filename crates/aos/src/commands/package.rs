//! `aos package` / `apm` — the AOS package manager.
//!
//! The entire implementation lives in the `aos-package` crate; this
//! module is a one-line bridge that forwards the parsed subcommand and
//! the global `--dry-run` / `--yes` flags. Invoking the binary as `apm`
//! (or `apr` for registry operations) lands here via the multicall
//! dispatch in `main.rs`.

use anyhow::Result;

use crate::cli::PackageArgs;
use aos_core::output::Printer;

/// `aos package` / `apm` — delegate to the package manager crate.
///
/// # Errors
///
/// Propagates any error from `aos_package::run` (resolution, install,
/// removal, or registry failures).
pub async fn run(args: &PackageArgs, printer: &Printer) -> Result<()> {
    aos_package::run(&args.command, args.dry_run, args.yes, printer).await
}
