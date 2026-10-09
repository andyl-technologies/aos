//! Package command adapter for verified registry metadata refresh.

use anyhow::Result;
use aos_cli_ui::output::Printer;
use aos_registry_client::config::ApmConfig;

/// Refreshes registries with the hint appropriate to this package runtime.
///
/// # Errors
///
/// Returns an error when registry selection, verification, transport, or
/// persistence fails.
pub async fn run(
    config: &ApmConfig,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    aos_registry_client::sync::run_with_options(
        config,
        registry_filter,
        printer,
        !crate::runtime_boundary::is_container(),
    )
    .await
}
