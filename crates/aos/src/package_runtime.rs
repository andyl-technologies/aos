//! `aos-package-runtime` is the private on-host package lifecycle helper.

/// Runs the private package-runtime CLI.
#[tokio::main]
async fn main() {
    aos::entry::package_runtime_main().await;
}
