//! Handles hub invitation commands and their domain-specific request validation.

use crate::cli::{HubInvitationCancelCmd, HubInvitationCmd, HubInvitationCreateCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    retained_apply_mutation, retained_plan_mutation, topology_mutation, topology_read,
};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub invitation command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn invitation(printer: &Printer, command: &HubInvitationCmd) -> Result<()> {
    match command {
        HubInvitationCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::ListInvitations,
                &hub_types::ListInvitationsRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubInvitationCmd::Show {
            access,
            org,
            invitation_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::GetInvitation,
                &hub_types::GetInvitationRequest {
                    org_slug: org.clone(),
                    invitation_id: *invitation_id,
                },
            )
            .await
        }
        HubInvitationCmd::Create { command } => match command {
            HubInvitationCreateCmd::Plan {
                request,
                org,
                email,
                scope,
                role,
                ttl,
            } => {
                let client =
                    hub_client(&request.access.hub, request.access.token.as_deref()).await?;
                let mutation = retained_plan_mutation(&request.idempotency_key, None);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateInvitation,
                    HubTopologyMethod::CreateInvitation,
                    &hub_types::PlanCreateInvitationRequest {
                        org_slug: org.clone(),
                        email: email.clone(),
                        scope: scope.clone(),
                        role: role.clone(),
                        ttl_secs: ttl.unwrap_or_default(),
                        expected_resource_version: String::new(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubInvitationCreateCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref()).await?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateInvitation,
                    HubTopologyMethod::CreateInvitation,
                    &hub_types::PlanCreateInvitationRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubInvitationCmd::Cancel { command } => match command {
            HubInvitationCancelCmd::Plan {
                request,
                org,
                invitation_id,
                if_version,
            } => {
                let client =
                    hub_client(&request.access.hub, request.access.token.as_deref()).await?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCancelInvitation,
                    HubTopologyMethod::CancelInvitation,
                    &hub_types::PlanCancelInvitationRequest {
                        org_slug: org.clone(),
                        invitation_id: *invitation_id,
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubInvitationCancelCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref()).await?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCancelInvitation,
                    HubTopologyMethod::CancelInvitation,
                    &hub_types::PlanCancelInvitationRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubInvitationCmd::Accept {
            access,
            org,
            secret,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::AcceptInvitation,
                &hub_types::AcceptInvitationRequest {
                    org_slug: org.clone(),
                    secret: secret.clone(),
                },
            )
            .await
        }
    }
}
