//! `apm` is the package-management entry point for the AOS multicall CLI.

mod cli;
mod commands;
mod entry;
mod logging;

/// Process entry point for the `apm` binary alias.
#[tokio::main]
async fn main() {
    entry::main().await;
}
