//! Shared installed entry point for the public `apm` command and the private
//! package runtime.

/// Selects the package command surface from the installed entry-point name.
#[tokio::main]
async fn main() {
    if aos_core::invocation::binary_name() == "aos-package-runtime" {
        aos::entry::package_runtime_main().await;
    } else {
        aos::entry::apm_main().await;
    }
}
