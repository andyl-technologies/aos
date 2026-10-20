//! Shared installed entry point for the public `apm` command and the private
//! package runtime and authenticated boot helper.

/// Selects the package command surface from the installed entry-point name.
#[tokio::main]
async fn main() {
    match aos_cli_ui::invocation::binary_name().as_str() {
        "aos-package-runtime" => aos_cli::entry::package_runtime_main().await,
        "aos-boot-configuration" => aos_cli::entry::boot_configuration_main(),
        _ => aos_cli::entry::apm_main().await,
    }
}
