//! Handles hub audit commands and their domain-specific request validation.

use crate::cli::HubAuditCmd;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub audit command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn audit(printer: &Printer, command: &HubAuditCmd) -> Result<()> {
    let HubAuditCmd::List {
        access,
        scope,
        pagination,
    } = command;
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_read::<_, hub_types::ListAuditResponse>(
        printer,
        &client,
        HubTopologyMethod::ListAudit,
        &hub_types::ListAuditRequest {
            scope: scope.clone(),
            page_size: pagination.page_size.unwrap_or_default(),
            page_token: pagination.page_token.clone().unwrap_or_default(),
        },
    )
    .await
}
