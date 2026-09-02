//! `apm` is the AOS package-consumer command-line tool.

/// Runs the `apm` CLI.
#[tokio::main]
async fn main() {
    aos::entry::apm_main().await;
}
