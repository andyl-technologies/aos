//! `apr` is the registry-operation entry point for the AOS multicall CLI.

mod cli;
mod commands;
mod entry;
mod logging;

/// Process entry point for the `apr` binary alias.
#[tokio::main]
async fn main() {
    entry::main().await;
}
