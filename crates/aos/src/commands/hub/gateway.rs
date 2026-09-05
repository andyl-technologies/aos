//! Handles hub gateway commands and their domain-specific request validation.

use crate::cli::{HubGatewayCmd, HubMutationArgs};
use crate::commands::hub::access_policy::build_access_policy;
use crate::commands::hub::binding::parse_binding_ref;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_generation_ref;
use crate::commands::hub::mutation::{
    consumer_scope_mutation, delete_topology_resource, new_idempotency_key, topology_mutation,
    topology_read, topology_stable_id, topology_state_mutation,
};
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{HubRpc, hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub gateway command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn gateway(printer: &Printer, command: &HubGatewayCmd) -> Result<()> {
    match command {
        HubGatewayCmd::List {
            access,
            binding,
            scope,
            include_granted,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListGatewaysResponse>(
                printer,
                &client,
                HubTopologyMethod::ListGateways,
                &hub_types::ListGatewaysRequest {
                    binding: binding.as_deref().map(parse_binding_ref).transpose()?,
                    owner_scope_key: scope.clone().unwrap_or_default(),
                    include_granted: *include_granted,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubGatewayCmd::Show { access, gateway } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GatewayResponse>(
                printer,
                &client,
                HubTopologyMethod::GetGateway,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: gateway.clone(),
                },
            )
            .await
        }
        HubGatewayCmd::Add {
            access,
            stable_id,
            binding,
            endpoint,
            client_base_path,
            origin_prefix,
            policy,
            mutation,
        } => {
            if policy.access.is_none() {
                anyhow::bail!("gateway add requires --access");
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let binding_response: hub_types::GetBindingResponse = client
                .call_topology(
                    HubTopologyMethod::GetBinding,
                    &hub_types::GetBindingRequest {
                        binding: Some(parse_binding_ref(binding)?),
                    },
                )
                .await?;
            let binding = binding_response
                .binding
                .context("Hub returned no binding")?;
            let owner_scope_key = binding.owner_scope_key;
            let binding_stable_id = binding.stable_id;
            let (endpoint_id, endpoint_generation) = endpoint
                .rsplit_once('@')
                .map(|(id, generation)| {
                    Ok::<_, anyhow::Error>((id.to_string(), generation.parse::<i64>()?))
                })
                .transpose()?
                .unwrap_or_else(|| (endpoint.clone(), 0));
            gateway_mutation(
                printer,
                access,
                HubTopologyMethod::PlanCreateGateway,
                HubTopologyMethod::CreateGateway,
                hub_types::PlanGatewayMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "storage-gateway"),
                    owner_scope_key,
                    revision: Some(hub_types::GatewayRevisionSpec {
                        binding_id: binding_stable_id,
                        endpoint_id,
                        endpoint_generation,
                        client_base_path: client_base_path.clone(),
                        origin_prefix: origin_prefix.clone(),
                        access_policy: build_access_policy(policy, false)?,
                    }),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
            )
            .await
        }
        HubGatewayCmd::Update {
            access,
            gateway,
            endpoint_generation,
            client_base_path,
            origin_prefix,
            policy,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                return gateway_mutation(
                    printer,
                    access,
                    HubTopologyMethod::PlanUpdateGateway,
                    HubTopologyMethod::UpdateGateway,
                    hub_types::PlanGatewayMutationRequest::default(),
                    mutation,
                )
                .await;
            }
            if endpoint_generation.is_none()
                && client_base_path.is_none()
                && origin_prefix.is_none()
                && policy.access.is_none()
            {
                anyhow::bail!("gateway update requires at least one changed field");
            }
            gateway_mutation(
                printer,
                access,
                HubTopologyMethod::PlanUpdateGateway,
                HubTopologyMethod::UpdateGateway,
                hub_types::PlanGatewayMutationRequest {
                    stable_id: gateway.clone(),
                    revision: Some(hub_types::GatewayRevisionSpec {
                        endpoint_generation: endpoint_generation
                            .map(|value| i64::try_from(value))
                            .transpose()?
                            .unwrap_or_default(),
                        client_base_path: client_base_path.clone().unwrap_or_default(),
                        origin_prefix: origin_prefix.clone().unwrap_or_default(),
                        access_policy: build_access_policy(policy, false)?,
                        ..Default::default()
                    }),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask: [
                        endpoint_generation
                            .as_ref()
                            .map(|_| "revision.endpoint_generation"),
                        client_base_path
                            .as_ref()
                            .map(|_| "revision.client_base_path"),
                        origin_prefix.as_ref().map(|_| "revision.origin_prefix"),
                        policy.access.as_ref().map(|_| "revision.access_policy"),
                    ]
                    .into_iter()
                    .flatten()
                    .map(str::to_string)
                    .collect(),
                    ..Default::default()
                },
                mutation,
            )
            .await
        }
        HubGatewayCmd::Grant {
            access,
            gateway_generation,
            consumer_scope,
            mutation,
        }
        | HubGatewayCmd::Revoke {
            access,
            gateway_generation,
            consumer_scope,
            mutation,
        } => {
            let (gateway_id, generation) = parse_generation_ref(gateway_generation, "gateway")?;
            let revoke = matches!(command, HubGatewayCmd::Revoke { .. });
            if revoke {
                consumer_scope_mutation(
                    printer,
                    access,
                    "gateway",
                    &gateway_id,
                    generation,
                    consumer_scope,
                    mutation,
                    HubTopologyMethod::PlanRevokeGatewayScope,
                    HubTopologyMethod::RevokeGatewayScope,
                )
                .await
            } else {
                consumer_scope_mutation(
                    printer,
                    access,
                    "gateway",
                    &gateway_id,
                    generation,
                    consumer_scope,
                    mutation,
                    HubTopologyMethod::PlanGrantGatewayScope,
                    HubTopologyMethod::GrantGatewayScope,
                )
                .await
            }
        }
        HubGatewayCmd::Preview { access, gateway } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GatewayRoutePreviewResponse>(
                printer,
                &client,
                HubTopologyMethod::PreviewGatewayRoutes,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: gateway.clone(),
                },
            )
            .await
        }
        HubGatewayCmd::Enable {
            access,
            gateway,
            mutation,
        } => {
            topology_state_mutation::<hub_types::GatewayResponse>(
                printer,
                access,
                gateway,
                mutation,
                HubTopologyMethod::PlanEnableGateway,
                HubTopologyMethod::EnableGateway,
            )
            .await
        }
        HubGatewayCmd::Disable {
            access,
            gateway,
            mutation,
        } => {
            topology_state_mutation::<hub_types::GatewayResponse>(
                printer,
                access,
                gateway,
                mutation,
                HubTopologyMethod::PlanDisableGateway,
                HubTopologyMethod::DisableGateway,
            )
            .await
        }
        HubGatewayCmd::Remove {
            access,
            gateway,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                gateway,
                mutation,
                HubTopologyMethod::PlanDeleteGateway,
                HubTopologyMethod::DeleteGateway,
            )
            .await
        }
    }
}

async fn gateway_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanGatewayMutationRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyGatewayMutationRequest,
        Response = hub_types::GatewayResponse,
    > + Copy,
    request: hub_types::PlanGatewayMutationRequest,
    mutation: &HubMutationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<_, hub_types::ApplyGatewayMutationRequest, hub_types::GatewayResponse, _>(
        printer,
        &client,
        plan_method,
        apply_method,
        &request,
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyGatewayMutationRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}
