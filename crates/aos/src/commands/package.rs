use anyhow::Result;

use crate::cli::PackageArgs;
use aos_core::output::Printer;

/// `aos package` / `apm` — delegate to the package manager crate.
pub async fn run(args: &PackageArgs, printer: &Printer) -> Result<()> {
    aos_package::run(&args.command, args.dry_run, args.yes, printer).await
}
