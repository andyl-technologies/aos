//! Handles hub identity provider commands and their domain-specific request validation.

use crate::cli::{HubIdentityProviderCmd, HubIdentityProviderRemoveCmd, HubIdentityProviderSetCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    retained_apply_mutation, retained_plan_mutation, topology_mutation, topology_read,
};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub identity provider command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn identity_provider(
    printer: &Printer,
    command: &HubIdentityProviderCmd,
) -> Result<()> {
    match command {
        HubIdentityProviderCmd::Show { access, org } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::GetIdentityProvider,
                &hub_types::GetIdentityProviderRequest {
                    org_slug: org.clone(),
                },
            )
            .await
        }
        HubIdentityProviderCmd::Set { command } => match command {
            HubIdentityProviderSetCmd::Plan {
                request,
                org,
                issuer,
                authorization_endpoint,
                token_endpoint,
                jwks_uri,
                client_id,
                client_secret,
                clear_client_secret,
                scopes,
                groups_claim,
                role_map_json,
                allow_jit,
                enforce_sso,
                default_role,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetIdentityProvider,
                    HubTopologyMethod::SetIdentityProvider,
                    &hub_types::PlanSetIdentityProviderRequest {
                        org_slug: org.clone(),
                        issuer: issuer.clone(),
                        authorization_endpoint: authorization_endpoint.clone(),
                        token_endpoint: token_endpoint.clone(),
                        jwks_uri: jwks_uri.clone(),
                        client_id: client_id.clone(),
                        client_secret: client_secret.clone().unwrap_or_default(),
                        replace_client_secret: client_secret.is_some() || *clear_client_secret,
                        scopes: scopes.clone(),
                        groups_claim: groups_claim.clone().unwrap_or_default(),
                        role_map_json: role_map_json.clone(),
                        allow_jit: *allow_jit,
                        enforce_sso: *enforce_sso,
                        default_role: default_role.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubIdentityProviderSetCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetIdentityProvider,
                    HubTopologyMethod::SetIdentityProvider,
                    &hub_types::PlanSetIdentityProviderRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubIdentityProviderCmd::Remove { command } => match command {
            HubIdentityProviderRemoveCmd::Plan {
                request,
                org,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRemoveIdentityProvider,
                    HubTopologyMethod::RemoveIdentityProvider,
                    &hub_types::PlanRemoveIdentityProviderRequest {
                        org_slug: org.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubIdentityProviderRemoveCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRemoveIdentityProvider,
                    HubTopologyMethod::RemoveIdentityProvider,
                    &hub_types::PlanRemoveIdentityProviderRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
    }
}
