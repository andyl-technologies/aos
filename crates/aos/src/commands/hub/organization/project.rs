//! Handles hub project commands and their domain-specific request validation.

use crate::cli::HubProjectCmd;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_project_plan;
use crate::commands::hub::mutation::{new_idempotency_key, topology_mutation, topology_read};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub project command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn project(
    printer: &Printer,
    command: &HubProjectCmd,
) -> Result<()> {
    match command {
        HubProjectCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListProjectsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListProjects,
                &hub_types::ListProjectsRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubProjectCmd::Create {
            access,
            org,
            path,
            name,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_mutation::<
                _,
                hub_types::ApplyProjectMutationRequest,
                hub_types::ProjectResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateProject,
                HubTopologyMethod::CreateProject,
                &hub_types::PlanCreateProjectRequest {
                    org_slug: org.clone(),
                    path: path.clone(),
                    name: name.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                apply_project_plan,
            )
            .await
        }
        HubProjectCmd::Show { access, org, path } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ProjectResponse>(
                printer,
                &client,
                HubTopologyMethod::GetProject,
                &hub_types::GetProjectRequest {
                    org_slug: org.clone(),
                    path: path.clone(),
                },
            )
            .await
        }
        HubProjectCmd::Delete {
            access,
            org,
            path,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_mutation::<
                _,
                hub_types::ApplyProjectMutationRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeleteProject,
                HubTopologyMethod::DeleteProject,
                &hub_types::PlanDeleteProjectRequest {
                    org_slug: org.clone(),
                    path: path.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_project_plan,
            )
            .await
        }
    }
}
