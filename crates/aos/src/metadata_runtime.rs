//! `aos-metadata-runtime` is the compact on-host metadata command.

use clap::Parser;

#[derive(Parser)]
#[command(name = "aos-metadata-runtime")]
struct Cli {
    #[command(subcommand)]
    command: aos_package::metadata::MetadataCommand,
}

/// Runs the metadata command surface without linking repository workflows.
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = aos_package::metadata::run_command(&cli.command).await {
        eprintln!("aos-metadata-runtime: {error:#}");
        std::process::exit(1);
    }
}
