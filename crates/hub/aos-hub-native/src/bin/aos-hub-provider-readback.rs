//! Bounded read-only provider observations using existing private credentials.
//!
//! This operator tool accepts a selection and credentials through inherited
//! private descriptors. It never uploads, changes policy, issues credentials,
//! retries a request, or upgrades an observation to storage authority.

use std::path::PathBuf;

use clap::Parser;

#[path = "../provider_readback/mod.rs"]
mod provider_readback;

#[derive(Parser)]
#[command(name = "aos-hub-provider-readback")]
struct Cli {
    /// Read the closed selection from an inherited private regular-file descriptor.
    #[arg(long)]
    selection_fd: u32,
    /// Consume existing credentials from an inherited private descriptor.
    #[arg(long)]
    credentials_fd: u32,
    /// Create a fresh observation directory below an existing private parent.
    #[arg(long)]
    output_dir: PathBuf,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let selected = Cli::parse();
    match provider_readback::run(
        selected.selection_fd,
        selected.credentials_fd,
        &selected.output_dir,
    )
    .await
    {
        Ok(()) => {
            println!("Read-only observations retained; permission and writer closure remain unqualified.");
            std::process::ExitCode::from(2)
        }
        Err(_) => {
            eprintln!("Read-only provider observation failed or is unknown; retained originals are not retried.");
            std::process::ExitCode::FAILURE
        }
    }
}
