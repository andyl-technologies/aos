//! Handles hub route commands and their domain-specific request validation.

use crate::cli::{HubMutationArgs, HubRouteCmd, HubRouteSpecArgs};
use crate::commands::hub::access_policy::{access_policy_args_present, build_access_policy};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_generation_ref;
use crate::commands::hub::mutation::{
    delete_topology_resource, new_idempotency_key, topology_mutation, topology_read,
    topology_stable_id, topology_state_mutation,
};
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{HubRpc, HubSurfaceRef, hub_rpc as HubTopologyMethod, hub_types};

/// Converts a qualified surface reference into the public API representation.
///
/// # Errors
///
/// Returns an error if the surface reference is invalid.
pub(super) fn surface_message(value: &str) -> Result<hub_types::SurfaceRef> {
    let surface: HubSurfaceRef = value.parse()?;
    let target = match surface {
        HubSurfaceRef::Registry(slug) => hub_types::surface_ref::Target::RegistrySlug(slug),
        HubSurfaceRef::Cache(slug) => hub_types::surface_ref::Target::CacheSlug(slug),
    };
    Ok(hub_types::SurfaceRef {
        target: Some(target),
    })
}

fn hub_delivery_kind(mode: &str) -> Result<i32> {
    match mode {
        "hub-proxy" => Ok(hub_types::HubDeliveryKind::Proxy as i32),
        "hub-redirect" => Ok(hub_types::HubDeliveryKind::Redirect as i32),
        other => anyhow::bail!("unsupported Hub route mode '{other}'"),
    }
}

/// Identifies the delivery mode encoded by a route specification.
///
/// # Errors
///
/// Returns an error if the route does not encode a supported delivery mode.
pub(super) fn route_mode(spec: &hub_types::RouteSpec) -> Result<&'static str> {
    match spec
        .target
        .as_ref()
        .and_then(|target| target.target.as_ref())
        .context("route requires a complete target")?
    {
        hub_types::route_target::Target::DirectGatewayPlacement(_) => Ok("direct"),
        hub_types::route_target::Target::HubPlacement(target) => {
            match hub_types::HubDeliveryKind::try_from(target.delivery_kind) {
                Ok(hub_types::HubDeliveryKind::Proxy) => Ok("hub-proxy"),
                Ok(hub_types::HubDeliveryKind::Redirect) => Ok("hub-redirect"),
                _ => anyhow::bail!("Hub placement target has no delivery kind"),
            }
        }
        hub_types::route_target::Target::HubPolicyRevision(target) => {
            match hub_types::HubDeliveryKind::try_from(target.delivery_kind) {
                Ok(hub_types::HubDeliveryKind::Proxy) => Ok("hub-proxy"),
                Ok(hub_types::HubDeliveryKind::Redirect) => Ok("hub-redirect"),
                _ => anyhow::bail!("Hub policy target has no delivery kind"),
            }
        }
    }
}

fn route_spec(
    surface: Option<&str>,
    input: &HubRouteSpecArgs,
    require_complete: bool,
) -> Result<hub_types::RouteSpec> {
    let mode = input.mode.clone().unwrap_or_default();
    if require_complete && mode.is_empty() {
        anyhow::bail!("--mode is required");
    }
    if require_complete && mode != "direct" && input.policy.access.is_none() {
        anyhow::bail!("Hub routes require --access");
    }
    let (endpoint_id, endpoint_generation) = match (&input.endpoint, input.endpoint_generation) {
        (Some(endpoint), explicit_generation) => {
            let parsed = endpoint
                .rsplit_once('@')
                .map(|(id, generation)| {
                    Ok::<_, anyhow::Error>((id.to_string(), generation.parse::<i64>()?))
                })
                .transpose()?;
            match (parsed, explicit_generation) {
                (Some((_, _)), Some(_)) => anyhow::bail!("endpoint generation was supplied twice"),
                (Some(value), None) => value,
                (None, generation) => (
                    endpoint.clone(),
                    generation
                        .map(i64::try_from)
                        .transpose()?
                        .unwrap_or_default(),
                ),
            }
        }
        (None, Some(generation)) => (String::new(), i64::try_from(generation)?),
        (None, None) if require_complete => anyhow::bail!("--endpoint is required"),
        (None, None) => (String::new(), 0),
    };
    if (require_complete || input.endpoint_generation.is_some()) && endpoint_generation <= 0 {
        anyhow::bail!("endpoint generation must be greater than zero");
    }
    if require_complete && endpoint_id.is_empty() {
        anyhow::bail!("endpoint stable id cannot be empty");
    }
    let target = if mode == "direct" || (mode.is_empty() && input.gateway.is_some()) {
        if input.placement_policy.is_some() {
            anyhow::bail!("direct routes reject --placement-policy");
        }
        if input.base_path.is_some() {
            anyhow::bail!("direct routes derive their path and reject --base-path");
        }
        if build_access_policy(&input.policy, true)?.is_some() {
            anyhow::bail!("direct routes derive access from the gateway generation");
        }
        let (gateway_id, gateway_generation) = parse_generation_ref(
            input
                .gateway
                .as_deref()
                .context("direct routes require --gateway")?,
            "gateway",
        )?;
        Some(hub_types::route_target::Target::DirectGatewayPlacement(
            hub_types::DirectGatewayPlacementTarget {
                placement_name: input
                    .placement
                    .clone()
                    .context("direct routes require --placement")?,
                gateway_id,
                gateway_generation,
            },
        ))
    } else if let Some(placement) = input.placement.as_ref() {
        if input.gateway.is_some() {
            anyhow::bail!("Hub routes reject --gateway");
        }
        Some(hub_types::route_target::Target::HubPlacement(
            hub_types::HubPlacementTarget {
                placement_name: placement.clone(),
                delivery_kind: hub_delivery_kind(&mode)?,
            },
        ))
    } else if let Some(policy) = input.placement_policy.as_ref() {
        let (policy_name, revision) = parse_generation_ref(policy, "placement policy")?;
        Some(hub_types::route_target::Target::HubPolicyRevision(
            hub_types::HubPolicyRevisionTarget {
                policy_name,
                revision,
                delivery_kind: hub_delivery_kind(&mode)?,
            },
        ))
    } else if require_complete {
        anyhow::bail!("Hub routes require --placement or --placement-policy");
    } else {
        None
    };
    let capabilities = hub_types::RouteCapabilities {
        serves_git: input.serves.iter().any(|value| value == "git"),
        serves_cache: input.serves.iter().any(|value| value == "cache"),
        serves_web: input.serves.iter().any(|value| value == "web"),
        serves_oci: input.serves.iter().any(|value| value == "oci"),
    };
    if require_complete && input.serves.is_empty() {
        anyhow::bail!("at least one --serves capability is required");
    }
    Ok(hub_types::RouteSpec {
        surface: surface.map(surface_message).transpose()?,
        endpoint_id,
        endpoint_generation,
        base_path: if mode == "direct" {
            String::new()
        } else if require_complete {
            input.base_path.clone().unwrap_or_else(|| "/".into())
        } else {
            input.base_path.clone().unwrap_or_default()
        },
        access_policy: if input.mode.as_deref() == Some("direct") {
            None
        } else {
            build_access_policy(&input.policy, true)?
        },
        target: target.map(|target| hub_types::RouteTarget {
            target: Some(target),
        }),
        capabilities: if require_complete || !input.serves.is_empty() {
            Some(capabilities)
        } else {
            None
        },
        enabled: false,
    })
}

fn merge_route_spec(
    mut current: hub_types::RouteSpec,
    input: &HubRouteSpecArgs,
) -> Result<hub_types::RouteSpec> {
    if input.endpoint.is_some() || input.base_path.is_some() {
        anyhow::bail!("route update preserves endpoint identity and path; use route replace");
    }
    if let Some(generation) = input.endpoint_generation {
        if generation == 0 {
            anyhow::bail!("endpoint generation must be greater than zero");
        }
        current.endpoint_generation = i64::try_from(generation)?;
    }
    if current.endpoint_id.is_empty() || current.endpoint_generation <= 0 {
        anyhow::bail!("route endpoint identity and positive generation are required");
    }

    let previous_mode = route_mode(&current)?.to_string();
    let mode = input.mode.as_deref().unwrap_or(&previous_mode).to_string();
    match mode.as_str() {
        "direct" => {
            if input.placement_policy.is_some() {
                anyhow::bail!("direct routes reject --placement-policy");
            }
            if input.policy.access.is_some() {
                anyhow::bail!("direct routes derive access and reject --access");
            }
            let switching = previous_mode != "direct";
            if switching && (input.gateway.is_none() || input.placement.is_none()) {
                anyhow::bail!("switching to direct requires both --gateway and --placement");
            }
            if input.gateway.is_some() || input.placement.is_some() {
                let existing =
                    current
                        .target
                        .as_ref()
                        .and_then(|target| match target.target.as_ref() {
                            Some(hub_types::route_target::Target::DirectGatewayPlacement(
                                target,
                            )) => Some(target),
                            _ => None,
                        });
                let (gateway_id, gateway_generation) = if let Some(gateway) =
                    input.gateway.as_deref()
                {
                    parse_generation_ref(gateway, "gateway")?
                } else {
                    let existing = existing.context("direct target update requires --gateway")?;
                    (existing.gateway_id.clone(), existing.gateway_generation)
                };
                let placement_name = input
                    .placement
                    .clone()
                    .or_else(|| existing.map(|target| target.placement_name.clone()))
                    .context("direct target update requires --placement")?;
                current.target = Some(hub_types::RouteTarget {
                    target: Some(hub_types::route_target::Target::DirectGatewayPlacement(
                        hub_types::DirectGatewayPlacementTarget {
                            placement_name,
                            gateway_id,
                            gateway_generation,
                        },
                    )),
                });
            }
            current.base_path.clear();
            current.access_policy = None;
        }
        "hub-proxy" | "hub-redirect" => {
            if input.gateway.is_some() {
                anyhow::bail!("Hub routes reject --gateway");
            }
            let switching = previous_mode == "direct";
            if switching
                && (input.placement.is_none() && input.placement_policy.is_none()
                    || input.policy.access.is_none())
            {
                anyhow::bail!("switching from direct requires a Hub target and explicit --access");
            }
            if let Some(placement) = input.placement.as_ref() {
                current.target = Some(hub_types::RouteTarget {
                    target: Some(hub_types::route_target::Target::HubPlacement(
                        hub_types::HubPlacementTarget {
                            placement_name: placement.clone(),
                            delivery_kind: hub_delivery_kind(&mode)?,
                        },
                    )),
                });
            } else if let Some(policy) = input.placement_policy.as_ref() {
                let (policy_name, revision) = parse_generation_ref(policy, "placement policy")?;
                current.target = Some(hub_types::RouteTarget {
                    target: Some(hub_types::route_target::Target::HubPolicyRevision(
                        hub_types::HubPolicyRevisionTarget {
                            policy_name,
                            revision,
                            delivery_kind: hub_delivery_kind(&mode)?,
                        },
                    )),
                });
            }
            if input.policy.access.is_some() {
                current.access_policy = build_access_policy(&input.policy, true)?;
            }
            if current.access_policy.is_none() {
                anyhow::bail!("Hub routes require an access policy");
            }
            if switching {
                current.base_path = "/".into();
            }
            let delivery_kind = hub_delivery_kind(&mode)?;
            match current
                .target
                .as_mut()
                .and_then(|target| target.target.as_mut())
            {
                Some(hub_types::route_target::Target::HubPlacement(target)) => {
                    target.delivery_kind = delivery_kind;
                }
                Some(hub_types::route_target::Target::HubPolicyRevision(target)) => {
                    target.delivery_kind = delivery_kind;
                }
                _ => anyhow::bail!("Hub route requires a Hub target"),
            }
        }
        other => anyhow::bail!("unsupported route mode '{other}'"),
    }
    if !input.serves.is_empty() {
        current.capabilities = Some(hub_types::RouteCapabilities {
            serves_git: input.serves.iter().any(|value| value == "git"),
            serves_cache: input.serves.iter().any(|value| value == "cache"),
            serves_web: input.serves.iter().any(|value| value == "web"),
            serves_oci: input.serves.iter().any(|value| value == "oci"),
        });
    }
    let target = current
        .target
        .as_ref()
        .and_then(|target| target.target.as_ref())
        .context("route requires a complete target")?;
    match target {
        hub_types::route_target::Target::DirectGatewayPlacement(target)
            if !target.placement_name.is_empty()
                && !target.gateway_id.is_empty()
                && target.gateway_generation > 0
                && current.access_policy.is_none() => {}
        hub_types::route_target::Target::HubPlacement(target)
            if !target.placement_name.is_empty()
                && target.delivery_kind != hub_types::HubDeliveryKind::Unspecified as i32
                && current.access_policy.is_some() => {}
        hub_types::route_target::Target::HubPolicyRevision(target)
            if !target.policy_name.is_empty()
                && target.revision > 0
                && target.delivery_kind != hub_types::HubDeliveryKind::Unspecified as i32
                && current.access_policy.is_some() => {}
        _ => anyhow::bail!("route mode and target are inconsistent or incomplete"),
    }
    if current.capabilities.is_none() {
        anyhow::bail!("route requires capabilities");
    }
    Ok(current)
}

fn route_update_mask(input: &HubRouteSpecArgs) -> Vec<String> {
    let mut mask = Vec::with_capacity(4);
    if input.endpoint_generation.is_some() {
        mask.push("spec.endpoint_generation".into());
    }
    if input.mode.is_some()
        || input.placement.is_some()
        || input.placement_policy.is_some()
        || input.gateway.is_some()
    {
        mask.push("spec.target".into());
    }
    if access_policy_args_present(&input.policy) {
        mask.push("spec.access_policy".into());
    }
    if !input.serves.is_empty() {
        mask.push("spec.capabilities".into());
    }
    mask
}

/// Handles the hub route command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn route(printer: &Printer, command: &HubRouteCmd) -> Result<()> {
    match command {
        HubRouteCmd::List {
            access,
            surface_ref,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRoutesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRoutes,
                &hub_types::ListRoutesRequest {
                    surface: Some(surface_message(surface_ref)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubRouteCmd::Add {
            access,
            surface_ref,
            stable_id,
            spec,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                return route_mutation(
                    printer,
                    access,
                    HubTopologyMethod::PlanCreateRoute,
                    HubTopologyMethod::CreateRoute,
                    hub_types::PlanRouteMutationRequest::default(),
                    mutation,
                )
                .await;
            }
            route_mutation(
                printer,
                access,
                HubTopologyMethod::PlanCreateRoute,
                HubTopologyMethod::CreateRoute,
                hub_types::PlanRouteMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "delivery-route"),
                    spec: Some(route_spec(Some(surface_ref), spec, true)?),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
            )
            .await
        }
        HubRouteCmd::Update {
            access,
            route,
            spec,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                return route_mutation(
                    printer,
                    access,
                    HubTopologyMethod::PlanUpdateRoute,
                    HubTopologyMethod::UpdateRoute,
                    hub_types::PlanRouteMutationRequest::default(),
                    mutation,
                )
                .await;
            }
            if spec.mode.is_none()
                && spec.endpoint_generation.is_none()
                && spec.placement.is_none()
                && spec.placement_policy.is_none()
                && spec.gateway.is_none()
                && !access_policy_args_present(&spec.policy)
                && spec.serves.is_empty()
            {
                anyhow::bail!("route update requires at least one changed field");
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let current: hub_types::RouteResponse = client
                .call_topology(
                    HubTopologyMethod::GetRoute,
                    &hub_types::GetTopologyResourceRequest {
                        stable_id: route.clone(),
                    },
                )
                .await?;
            let current_spec = current
                .route
                .and_then(|route| route.spec)
                .context("the Hub returned a route without a specification")?;
            route_mutation(
                printer,
                access,
                HubTopologyMethod::PlanUpdateRoute,
                HubTopologyMethod::UpdateRoute,
                hub_types::PlanRouteMutationRequest {
                    stable_id: route.clone(),
                    spec: Some(merge_route_spec(current_spec, spec)?),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask: route_update_mask(spec),
                },
                mutation,
            )
            .await
        }
        HubRouteCmd::Replace {
            access,
            route,
            spec,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanReplaceRoute,
                    HubTopologyMethod::ReplaceRoute,
                    &hub_types::PlanReplaceRouteRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyRouteMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let predecessor: hub_types::RouteResponse = client
                .call_topology(
                    HubTopologyMethod::GetRoute,
                    &hub_types::GetTopologyResourceRequest {
                        stable_id: route.clone(),
                    },
                )
                .await?;
            let surface = predecessor
                .route
                .and_then(|route| route.spec)
                .and_then(|spec| spec.surface)
                .context("the Hub returned a predecessor route without a surface")?;
            let mut replacement_spec = route_spec(None, spec, true)?;
            replacement_spec.surface = Some(surface);
            topology_mutation::<
                _,
                hub_types::ApplyRouteMutationRequest,
                hub_types::RouteResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanReplaceRoute,
                HubTopologyMethod::ReplaceRoute,
                &hub_types::PlanReplaceRouteRequest {
                    predecessor_route_id: route.clone(),
                    stable_id: topology_stable_id(None, "delivery-route"),
                    spec: Some(replacement_spec),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyRouteMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubRouteCmd::Explain {
            access,
            route,
            path,
            access_class,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ExplainRouteResponse>(
                printer,
                &client,
                HubTopologyMethod::ExplainRoute,
                &hub_types::ExplainRouteRequest {
                    route_id: route.clone(),
                    machine_path: path.clone().unwrap_or_default(),
                    access_class: access_class.clone(),
                    ..Default::default()
                },
            )
            .await
        }
        HubRouteCmd::Enable {
            access,
            route,
            mutation,
        } => {
            topology_state_mutation::<hub_types::RouteResponse>(
                printer,
                access,
                route,
                mutation,
                HubTopologyMethod::PlanEnableRoute,
                HubTopologyMethod::EnableRoute,
            )
            .await
        }
        HubRouteCmd::Disable {
            access,
            route,
            mutation,
        } => {
            topology_state_mutation::<hub_types::RouteResponse>(
                printer,
                access,
                route,
                mutation,
                HubTopologyMethod::PlanDisableRoute,
                HubTopologyMethod::DisableRoute,
            )
            .await
        }
        HubRouteCmd::Remove {
            access,
            route,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                route,
                mutation,
                HubTopologyMethod::PlanDeleteRoute,
                HubTopologyMethod::DeleteRoute,
            )
            .await
        }
        HubRouteCmd::Canonical {
            access,
            surface_ref,
            route,
            audience,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyRouteAdvertisementRequest,
                hub_types::RouteAdvertisementResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanSetRouteAdvertisement,
                HubTopologyMethod::SetRouteAdvertisement,
                &hub_types::PlanRouteAdvertisementRequest {
                    surface: Some(surface_message(surface_ref)?),
                    audience: audience.clone(),
                    route_id: route.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyRouteAdvertisementRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
    }
}

async fn route_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanRouteMutationRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyRouteMutationRequest,
        Response = hub_types::RouteResponse,
    > + Copy,
    request: hub_types::PlanRouteMutationRequest,
    mutation: &HubMutationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<_, hub_types::ApplyRouteMutationRequest, hub_types::RouteResponse, _>(
        printer,
        &client,
        plan_method,
        apply_method,
        &request,
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyRouteMutationRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::HubAccessPolicyArgs;

    #[test]
    fn route_update_masks_name_each_changed_wire_field_once() {
        let input = HubRouteSpecArgs {
            endpoint: None,
            endpoint_generation: Some(2),
            base_path: None,
            mode: Some("hub-proxy".into()),
            placement: Some("primary".into()),
            placement_policy: None,
            gateway: None,
            serves: vec!["web".into()],
            policy: HubAccessPolicyArgs {
                access: Some("public".into()),
                ..Default::default()
            },
        };

        assert_eq!(
            route_update_mask(&input),
            [
                "spec.endpoint_generation",
                "spec.target",
                "spec.access_policy",
                "spec.capabilities",
            ]
        );
    }
}
