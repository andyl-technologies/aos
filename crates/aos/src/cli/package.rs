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
