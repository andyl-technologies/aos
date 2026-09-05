//! Handles hub service account commands and their domain-specific request validation.

use crate::cli::{
    HubServiceAccountCmd, HubServiceAccountCreateCmd, HubServiceAccountDeleteCmd,
    HubServiceAccountUpdateCmd,
};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    retained_apply_mutation, retained_plan_mutation, topology_mutation, topology_read,
};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub service account command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn service_account(
    printer: &Printer,
    command: &HubServiceAccountCmd,
) -> Result<()> {
    match command {
        HubServiceAccountCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::ListServiceAccounts,
                &hub_types::ListServiceAccountsRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubServiceAccountCmd::Show { access, org, name } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::GetServiceAccount,
                &hub_types::GetServiceAccountRequest {
                    org_slug: org.clone(),
                    name: name.clone(),
                },
            )
            .await
        }
        HubServiceAccountCmd::Create { command } => match command {
            HubServiceAccountCreateCmd::Plan {
                request,
                org,
                name,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, if_version.as_deref());
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateServiceAccount,
                    HubTopologyMethod::CreateServiceAccount,
                    &hub_types::PlanCreateServiceAccountRequest {
                        org_slug: org.clone(),
                        name: name.clone(),
                        expected_resource_version: if_version.clone().unwrap_or_default(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubServiceAccountCreateCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateServiceAccount,
                    HubTopologyMethod::CreateServiceAccount,
                    &hub_types::PlanCreateServiceAccountRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubServiceAccountCmd::Update { command } => match command {
            HubServiceAccountUpdateCmd::Plan {
                request,
                org,
                name,
                new_name,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateServiceAccount,
                    HubTopologyMethod::UpdateServiceAccount,
                    &hub_types::PlanUpdateServiceAccountRequest {
                        org_slug: org.clone(),
                        name: name.clone(),
                        new_name: new_name.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubServiceAccountUpdateCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateServiceAccount,
                    HubTopologyMethod::UpdateServiceAccount,
                    &hub_types::PlanUpdateServiceAccountRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubServiceAccountCmd::Delete { command } => match command {
            HubServiceAccountDeleteCmd::Plan {
                request,
                org,
                name,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanDeleteServiceAccount,
                    HubTopologyMethod::DeleteServiceAccount,
                    &hub_types::PlanDeleteServiceAccountRequest {
                        org_slug: org.clone(),
                        name: name.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubServiceAccountDeleteCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanDeleteServiceAccount,
                    HubTopologyMethod::DeleteServiceAccount,
                    &hub_types::PlanDeleteServiceAccountRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
    }
}
