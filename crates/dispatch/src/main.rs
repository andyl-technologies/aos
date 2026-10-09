//! Standalone JSON interface for portable assignment planning and execution.

mod cli;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    cli::run().await
}
