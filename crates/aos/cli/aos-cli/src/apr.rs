//! `apr` is the AOS registry-authoring command-line tool.

/// Runs the `apr` CLI.
#[tokio::main]
async fn main() {
    aos_cli::entry::apr_main().await;
}
