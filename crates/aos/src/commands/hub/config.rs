//! Handles hub config commands and their domain-specific request validation.

use crate::cli::HubConfigCmd;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub config command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn config(printer: &Printer, command: &HubConfigCmd) -> Result<()> {
    match command {
        HubConfigCmd::Changesets {
            access,
            scope,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListChangesetsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListChangesets,
                &hub_types::ListChangesetsRequest {
                    scope: scope.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubConfigCmd::Show { access, change_id } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::GetChangesetResponse>(
                printer,
                &client,
                HubTopologyMethod::GetChangeset,
                &hub_types::GetChangesetRequest {
                    change_id: change_id.clone(),
                },
            )
            .await
        }
        HubConfigCmd::Log {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::GitLogResponse>(
                printer,
                &client,
                HubTopologyMethod::GitLog,
                &hub_types::GitLogRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubConfigCmd::Diff {
            access,
            registry,
            from,
            to,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::GitDiffResponse>(
                printer,
                &client,
                HubTopologyMethod::GitDiff,
                &hub_types::GitDiffRequest {
                    slug: registry.clone(),
                    from_oid: from.clone().unwrap_or_default(),
                    to_oid: to.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubConfigCmd::ChangeRequests {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListChangeRequestsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListChangeRequests,
                &hub_types::ListChangeRequestsRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
    }
}
