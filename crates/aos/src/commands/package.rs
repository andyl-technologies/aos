use anyhow::Result;

use aos_core::output::Printer;
use crate::cli::PackageArgs;

/// `aos package` / `apm` — delegate to the package manager crate.
pub async fn run(args: &PackageArgs, printer: &Printer) -> Result<()> {
    aos_package::run(args.system, &args.command, args.dry_run, args.yes, printer).await
}
