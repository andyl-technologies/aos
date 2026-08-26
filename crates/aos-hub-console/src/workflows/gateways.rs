//! Storage-gateway inventory and lifecycle workflows.
//!
//! Gateways bind one binding to an exact delivery-endpoint generation.
//! Inventory follows the API's binding-scoped read model so operators can see
//! which storage origin each direct-delivery path exposes.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HelpTooltip, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::access_policy::{
    access_policy_name, canonical_path, required, AccessPolicyFields, AccessPolicySignals,
};
use super::instance_settings::InstanceSettingsWorkflow;
use super::organization_scope::organization_authorization_scope;

/// Renders storage-gateway workflows and delegates unrelated pages onward.
#[component]
pub(super) fn GatewayWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "gateways") => view! {
            <Gateways client=client scope=GatewayScope::Instance creation_only=false/>
        }
        .into_any(),
        (ConsoleScope::Instance, "gateways-new") => view! {
            <Gateways client=client scope=GatewayScope::Instance creation_only=true/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "gateways") => view! {
            <OrganizationGateways client=client organization=slug.clone() creation_only=false/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "gateways-new") => view! {
            <OrganizationGateways client=client organization=slug.clone() creation_only=true/>
        }
        .into_any(),
        _ => view! { <InstanceSettingsWorkflow route=route client=client/> }.into_any(),
    }
}

#[derive(Clone, Debug)]
enum GatewayScope {
    Instance,
    Organization {
        slug: String,
        owner_scope_key: String,
    },
}

impl GatewayScope {
    fn owner_scope_key(&self) -> String {
        match self {
            Self::Instance => "instance".to_string(),
            Self::Organization {
                owner_scope_key, ..
            } => owner_scope_key.clone(),
        }
    }

    fn binding_ref(&self, binding_name: &str) -> aos_proto_types::BindingRef {
        use aos_proto_types::binding_ref::Target;

        let target = match self {
            Self::Instance => Target::InstanceDefault(true),
            Self::Organization { slug, .. } => {
                Target::Organization(aos_proto_types::OrganizationBindingRef {
                    org_slug: slug.clone(),
                    name: binding_name.to_string(),
                })
            }
        };
        aos_proto_types::BindingRef {
            target: Some(target),
        }
    }
}

#[derive(Clone, Debug)]
struct GatewayInventory {
    binding_name: String,
    gateways: Vec<aos_proto_types::Gateway>,
}

#[derive(Clone, Debug)]
struct GatewayCreateChoices {
    bindings: Vec<aos_proto_types::Binding>,
    endpoints: Vec<aos_proto_types::Endpoint>,
    boundaries: Vec<aos_proto_types::NetworkPolicy>,
}

#[component]
fn OrganizationGateways(
    client: ApiClient,
    organization: String,
    creation_only: bool,
) -> impl IntoView {
    let resolve_client = client.clone();
    let resolve_slug = organization.clone();
    let scope = LocalResource::new(move || {
        let client = resolve_client.clone();
        let slug = resolve_slug.clone();
        async move { organization_authorization_scope(&client, slug).await }
    });

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Resolving organization scope…"</p> }>
            {move || {
                let client = client.clone();
                let slug = organization.clone();
                Suspend::new(async move {
                    match scope.await.as_ref() {
                        Ok(owner_scope_key) => view! {
                            <Gateways
                                client=client
                                scope=GatewayScope::Organization {
                                    slug,
                                    owner_scope_key: owner_scope_key.clone(),
                                }
                                creation_only=creation_only
                            />
                        }
                        .into_any(),
                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn Gateways(client: ApiClient, scope: GatewayScope, creation_only: bool) -> impl IntoView {
    let inventory_client = client.clone();
    let inventory_scope = scope.clone();
    let inventory = LocalResource::new(move || {
        let client = inventory_client.clone();
        let scope = inventory_scope.clone();
        async move { load_gateway_inventory(&client, &scope).await }
    });
    let view_client = client.clone();
    let create_scope = scope;
    let create_href = match (&create_scope, client.allows("gateway.manage")) {
        (GatewayScope::Organization { slug, .. }, true) => {
            Some(format!("/-/org/{slug}/gateways/new"))
        }
        (GatewayScope::Instance, true) => Some("/-/instance/gateways/new".to_string()),
        _ => None,
    };

    view! {
        <div class="workflow-stack">
            {(!creation_only).then(|| view! { <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"Direct storage delivery"</p>
                        <div class="section-title">
                            <h2>"Gateways"</h2>
                            <HelpTooltip term="Gateways" summary="Each gateway exposes one binding through an exact endpoint generation and access policy."/>
                        </div>
                    </div>
                    {create_href.map(|href| view! { <a class="button" href=href>"Create gateway"</a> })}
                </div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading gateways…"</p> }>
                    {move || {
                        let client = view_client.clone();
                        Suspend::new(async move {
                            match inventory.await.as_ref() {
                                Ok(groups) if groups.iter().all(|group| group.gateways.is_empty()) => {
                                    view! { <p class="muted">"No gateways in this scope."</p> }.into_any()
                                }
                                Ok(groups) => view! {
                                    <div class="binding-list">
                                        {groups.iter().cloned().map(|group| view! {
                                            <GatewayBindingGroup client=client.clone() inventory=group/>
                                        }).collect_view()}
                                    </div>
                                }.into_any(),
                                Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section> })}
            {creation_only.then(|| view! { <GatewayCreate client=client scope=create_scope/> })}
        </div>
    }
}

async fn load_gateway_inventory(
    client: &ApiClient,
    scope: &GatewayScope,
) -> Result<Vec<GatewayInventory>, String> {
    let binding_names = match scope {
        GatewayScope::Instance => vec!["default".to_string()],
        GatewayScope::Organization { .. } => client
            .collect_pages::<_, aos_proto_types::ListBindingsResponse, _, _, _>(
                aos_proto_types::BINDING_SERVICE_LIST_BINDINGS_PATH,
                move |page_token| aos_proto_types::ListBindingsRequest {
                    owner_scope_key: scope.owner_scope_key(),
                    page_size: 100,
                    page_token,
                },
                |response| (response.bindings, response.next_page_token),
            )
            .await
            .map_err(|failure| failure.to_string())?
            .into_iter()
            .filter_map(|binding| binding.spec.map(|spec| spec.name))
            .collect(),
    };

    let mut inventory = Vec::with_capacity(binding_names.len());
    for binding_name in binding_names {
        let binding = scope.binding_ref(&binding_name);
        let gateways = client
            .collect_pages::<_, aos_proto_types::ListGatewaysResponse, _, _, _>(
                aos_proto_types::DELIVERY_SERVICE_LIST_GATEWAYS_PATH,
                move |page_token| aos_proto_types::ListGatewaysRequest {
                    binding: Some(binding.clone()),
                    page_size: 100,
                    page_token,
                },
                |response| (response.gateways, response.next_page_token),
            )
            .await
            .map_err(|failure| failure.to_string())?;
        inventory.push(GatewayInventory {
            binding_name,
            gateways,
        });
    }
    Ok(inventory)
}

#[component]
fn GatewayBindingGroup(client: ApiClient, inventory: GatewayInventory) -> impl IntoView {
    view! {
        <section class="subworkflow">
            <div class="section-heading compact-heading">
                <div>
                    <span>"Binding"</span>
                    <code>{inventory.binding_name}</code>
                </div>
            </div>
            <div class="binding-list">
                {inventory.gateways.into_iter().map(|gateway| view! {
                    <GatewayCard client=client.clone() gateway=gateway/>
                }).collect_view()}
            </div>
        </section>
    }
}

#[component]
fn GatewayCreate(client: ApiClient, scope: GatewayScope) -> impl IntoView {
    let choices_client = client.clone();
    let choices_scope = scope.clone();
    let choices = LocalResource::new(move || {
        let client = choices_client.clone();
        let scope = choices_scope.clone();
        async move { load_gateway_create_choices(&client, &scope).await }
    });

    view! {
        <Suspense fallback=move || view! { <section class="panel editor-panel"><p class="loading-row">"Loading bindings and endpoints…"</p></section> }>
            {move || {
                let client = client.clone();
                let scope = scope.clone();
                Suspend::new(async move {
                    match choices.await.as_ref() {
                        Ok(choices) => view! { <GatewayCreateForm client=client scope=scope choices=choices.clone()/> }.into_any(),
                        Err(detail) => view! { <section class="panel editor-panel"><InlineError detail=detail.clone()/></section> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

async fn load_gateway_create_choices(
    client: &ApiClient,
    scope: &GatewayScope,
) -> Result<GatewayCreateChoices, String> {
    let owner_scope_key = scope.owner_scope_key();
    let binding_scope = owner_scope_key.clone();
    let bindings = client
        .collect_pages::<_, aos_proto_types::ListBindingsResponse, _, _, _>(
            aos_proto_types::BINDING_SERVICE_LIST_BINDINGS_PATH,
            move |page_token| aos_proto_types::ListBindingsRequest {
                owner_scope_key: binding_scope.clone(),
                page_size: 100,
                page_token,
            },
            |response| (response.bindings, response.next_page_token),
        )
        .await
        .map_err(|failure| failure.to_string())?;
    let endpoint_scope = owner_scope_key.clone();
    let endpoints = client
        .collect_pages::<_, aos_proto_types::ListEndpointsResponse, _, _, _>(
            aos_proto_types::DELIVERY_SERVICE_LIST_ENDPOINTS_PATH,
            move |page_token| aos_proto_types::ListTopologyResourcesRequest {
                owner_scope_key: endpoint_scope.clone(),
                page_size: 100,
                page_token,
            },
            |response| (response.endpoints, response.next_page_token),
        )
        .await
        .map_err(|failure| failure.to_string())?;
    let boundaries = client
        .collect_pages::<_, aos_proto_types::ListNetworkPoliciesResponse, _, _, _>(
            aos_proto_types::NETWORK_POLICY_SERVICE_LIST_NETWORK_POLICIES_PATH,
            move |page_token| aos_proto_types::ListTopologyResourcesRequest {
                owner_scope_key: owner_scope_key.clone(),
                page_size: 100,
                page_token,
            },
            |response| (response.network_policies, response.next_page_token),
        )
        .await
        .map_err(|failure| failure.to_string())?;

    Ok(GatewayCreateChoices {
        bindings,
        endpoints,
        boundaries,
    })
}

#[component]
fn GatewayCreateForm(
    client: ApiClient,
    scope: GatewayScope,
    choices: GatewayCreateChoices,
) -> impl IntoView {
    let stable_id = RwSignal::new(String::new());
    let binding_id = RwSignal::new(
        choices
            .bindings
            .first()
            .map(|binding| binding.stable_id.clone())
            .unwrap_or_default(),
    );
    let endpoint_id = RwSignal::new(
        choices
            .endpoints
            .first()
            .map(|endpoint| endpoint.stable_id.clone())
            .unwrap_or_default(),
    );
    let endpoint_generation = RwSignal::new(
        choices
            .endpoints
            .first()
            .map(|endpoint| endpoint.desired_generation.to_string())
            .unwrap_or_default(),
    );
    let client_base_path = RwSignal::new("/".to_string());
    let origin_prefix = RwSignal::new("/".to_string());
    let access = AccessPolicySignals::public();
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let binding_choices = choices.bindings;
    let endpoint_choices = choices.endpoints.clone();
    let selected_endpoints = choices.endpoints;
    let boundaries = choices.boundaries;
    let on_endpoint_change = move |event| {
        let value = event_target_value(&event);
        endpoint_id.set(value.clone());
        let generation = selected_endpoints
            .iter()
            .find(|endpoint| endpoint.stable_id == value)
            .map(|endpoint| endpoint.desired_generation.to_string())
            .unwrap_or_default();
        endpoint_generation.set(generation);
    };
    let owner_scope_key = scope.owner_scope_key();
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let revision = match gateway_revision(
            &binding_id.get_untracked(),
            &endpoint_id.get_untracked(),
            &endpoint_generation.get_untracked(),
            &client_base_path.get_untracked(),
            &origin_prefix.get_untracked(),
            access,
        ) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("gateway-create");
        let request = aos_proto_types::PlanGatewayMutationRequest {
            stable_id: stable_id.get_untracked().trim().to_string(),
            owner_scope_key: owner_scope_key.clone(),
            revision: Some(revision),
            carry_forward_consumer_scopes: Vec::new(),
            expected_resource_version: String::new(),
            idempotency_key: idempotency_key.clone(),
            update_mask: Vec::new(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_CREATE_GATEWAY_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::GatewayResponse>(
                    aos_proto_types::DELIVERY_SERVICE_CREATE_GATEWAY_PATH,
                    &reviewed.gateway_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="panel editor-panel">
            <div class="section-heading"><div><p class="section-kicker">"Guided setup"</p><h2>"Create gateway"</h2><p>"Choose the storage and endpoint by name. The gateway pins the endpoint's selected generation automatically."</p></div></div>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Gateway name"</span><input required prop:value=move || stable_id.get() on:input=move |event| stable_id.set(event_target_value(&event))/></label>
                <label><span>"Binding"</span><select required prop:value=move || binding_id.get() on:change=move |event| binding_id.set(event_target_value(&event))>{binding_choices.iter().map(|binding| view! { <option value=binding.stable_id.clone()>{binding_option_label(binding)}</option> }).collect_view()}</select>{binding_choices.is_empty().then(|| view! { <small>"No bindings exist in this scope."</small> })}</label>
                <label><span>"Endpoint"</span><select required prop:value=move || endpoint_id.get() on:change=on_endpoint_change>{endpoint_choices.iter().map(|endpoint| view! { <option value=endpoint.stable_id.clone()>{endpoint_option_label(endpoint)}</option> }).collect_view()}</select>{endpoint_choices.is_empty().then(|| view! { <small>"No endpoints exist in this scope. Create one first."</small> })}</label>
                <label><span>"Endpoint generation"</span><input readonly aria-readonly="true" prop:value=move || endpoint_generation.get()/><small>"Pins the endpoint's currently selected generation."</small></label>
                <label><span>"Client base path"</span><input required prop:value=move || client_base_path.get() on:input=move |event| client_base_path.set(event_target_value(&event))/></label>
                <label><span>"Origin prefix"</span><input required prop:value=move || origin_prefix.get() on:input=move |event| origin_prefix.set(event_target_value(&event))/></label>
                <AccessPolicyFields signals=access boundaries=boundaries/>
                <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get() || binding_id.get().is_empty() || endpoint_id.get().is_empty()>"Review creation"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

/// Formats one binding for a scoped resource selector.
pub(super) fn binding_option_label(binding: &aos_proto_types::Binding) -> String {
    let name = binding
        .spec
        .as_ref()
        .map(|spec| spec.name.as_str())
        .unwrap_or("unnamed");
    format!("{name} · {}", storage_provider_label(binding))
}

fn storage_provider_label(binding: &aos_proto_types::Binding) -> &'static str {
    use aos_proto_types::binding_spec::Provider;

    match binding
        .spec
        .as_ref()
        .and_then(|spec| spec.provider.as_ref())
    {
        Some(Provider::LocalFilesystem(_)) => "Local filesystem",
        Some(Provider::S3(_)) => "S3-compatible",
        Some(Provider::R2(_)) => "Cloudflare R2 API",
        Some(Provider::DeploymentR2(_)) => "Worker R2 deployment bucket",
        None => "Unknown provider",
    }
}

/// Formats one endpoint with the generation a new reference will pin.
pub(super) fn endpoint_option_label(endpoint: &aos_proto_types::Endpoint) -> String {
    format!(
        "{} · generation {}",
        endpoint_origin_label(endpoint),
        endpoint.desired_generation
    )
}

/// Formats one gateway with its pinned endpoint and desired generation.
pub(super) fn gateway_option_label(gateway: &aos_proto_types::Gateway) -> String {
    let desired = gateway.desired.as_ref();
    let endpoint = desired
        .map(|revision| format!("{}@{}", revision.endpoint_id, revision.endpoint_generation))
        .unwrap_or_else(|| "unconfigured endpoint".to_string());
    format!(
        "{} · generation {} · {endpoint}",
        gateway.stable_id, gateway.desired_generation
    )
}

fn endpoint_origin_label(endpoint: &aos_proto_types::Endpoint) -> String {
    use aos_proto_types::endpoint_host::Host;

    let host = endpoint
        .host
        .as_ref()
        .and_then(|value| value.host.as_ref())
        .map(|host| match host {
            Host::DomainId(domain) => domain.clone(),
            Host::Ipv4(bytes) => bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("."),
            Host::Ipv6(bytes) => bytes
                .chunks_exact(2)
                .map(|part| format!("{:02x}{:02x}", part[0], part[1]))
                .collect::<Vec<_>>()
                .join(":"),
        })
        .unwrap_or_else(|| "unknown host".to_string());
    format!("{}://{}:{}", endpoint.scheme, host, endpoint.effective_port)
}

#[component]
fn GatewayCard(client: ApiClient, gateway: aos_proto_types::Gateway) -> impl IntoView {
    let desired = gateway.desired.clone().unwrap_or_default();
    let state = if gateway.reconciliation_state.is_empty() {
        "unknown".to_string()
    } else {
        gateway.reconciliation_state.clone()
    };
    let positive = gateway.enabled && state == "ready";

    view! {
        <details class="binding-card">
            <summary>
                <div>
                    <span class="resource-kind">{if gateway.enabled { "enabled" } else { "disabled" }}</span>
                    <h3>{gateway.stable_id.clone()}</h3>
                    <code>{format!("{} → {}@{}", desired.binding_id, desired.endpoint_id, desired.endpoint_generation)}</code>
                </div>
                <div class="binding-summary-state"><StatusBadge state=state positive=positive/></div>
            </summary>
            <div class="binding-details">
                <div class="resource-identity">
                    <div><span>"Client path"</span><code>{desired.client_base_path.clone()}</code></div>
                    <div><span>"Origin prefix"</span><code>{desired.origin_prefix.clone()}</code></div>
                    <div><span>"Desired generation"</span><strong>{gateway.desired_generation}</strong></div>
                    <div><span>"Observed generation"</span><strong>{gateway.observed_generation}</strong></div>
                    <div><span>"Access"</span><strong>{access_policy_name(desired.access_policy.as_ref())}</strong></div>
                    <div><span>"Version"</span><code>{gateway.resource_version.clone()}</code></div>
                </div>
                {(!gateway.reconciliation_error.is_empty()).then(|| view! { <InlineError detail=gateway.reconciliation_error.clone()/> })}
                <GatewayPreview client=client.clone() gateway_id=gateway.stable_id.clone()/>
                <div class="subworkflow-grid">
                    <GatewayUpdate client=client.clone() gateway=gateway.clone()/>
                    <GatewayGrants client=client.clone() gateway=gateway.clone()/>
                </div>
                <div class="subworkflow-grid">
                    <GatewayState client=client.clone() gateway=gateway.clone()/>
                    <GatewayDelete client=client gateway=gateway/>
                </div>
            </div>
        </details>
    }
}

#[component]
fn GatewayPreview(client: ApiClient, gateway_id: String) -> impl IntoView {
    let preview = LocalResource::new(move || {
        let client = client.clone();
        let stable_id = gateway_id.clone();
        async move {
            client
                .call::<_, aos_proto_types::GatewayRoutePreviewResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PREVIEW_GATEWAY_ROUTES_PATH,
                    &aos_proto_types::GetTopologyResourceRequest { stable_id },
                )
                .await
        }
    });

    view! {
        <section class="subworkflow">
            <h4>"Direct-route preview"</h4>
            <Suspense fallback=move || view! { <p class="loading-row">"Resolving routes…"</p> }>
                {move || Suspend::new(async move {
                    match preview.await.as_ref() {
                        Ok(response) if response.routes.is_empty() => view! { <p class="muted">"No routes resolve from this gateway yet."</p> }.into_any(),
                        Ok(response) => view! {
                            <div class="compact-list">
                                {response.routes.iter().map(|route| view! {
                                    <div class="compact-list-row">
                                        <div>
                                            <code>{route.canonical_url.clone()}</code>
                                            <span>{format!("placement {} · base {}", route.placement_name, route.base_path)}</span>
                                            {(!route.warnings.is_empty()).then(|| view! { <span>{route.warnings.join(" · ")}</span> })}
                                        </div>
                                    </div>
                                }).collect_view()}
                            </div>
                        }.into_any(),
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn GatewayUpdate(client: ApiClient, gateway: aos_proto_types::Gateway) -> impl IntoView {
    let desired = gateway.desired.unwrap_or_default();
    let generations_client = client.clone();
    let generations_endpoint = desired.endpoint_id.clone();
    let endpoint_generations = LocalResource::new(move || {
        let client = generations_client.clone();
        let endpoint_id = generations_endpoint.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListEndpointGenerationsResponse, _, _, _>(
                    aos_proto_types::DELIVERY_SERVICE_LIST_ENDPOINT_GENERATIONS_PATH,
                    move |page_token| aos_proto_types::ListEndpointGenerationsRequest {
                        endpoint_id: endpoint_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.generations, response.next_page_token),
                )
                .await
        }
    });
    let endpoint_generation = RwSignal::new(desired.endpoint_generation.to_string());
    let client_base_path = RwSignal::new(desired.client_base_path);
    let origin_prefix = RwSignal::new(desired.origin_prefix);
    let access = AccessPolicySignals::from_policy(desired.access_policy);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let stable_id = gateway.stable_id;
    let version = gateway.resource_version;
    let binding_id = desired.binding_id;
    let endpoint_id = desired.endpoint_id;
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let revision = match gateway_revision(
            &binding_id,
            &endpoint_id,
            &endpoint_generation.get_untracked(),
            &client_base_path.get_untracked(),
            &origin_prefix.get_untracked(),
            access,
        ) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("gateway-update");
        let request = aos_proto_types::PlanGatewayMutationRequest {
            stable_id: stable_id.clone(),
            owner_scope_key: String::new(),
            revision: Some(revision),
            carry_forward_consumer_scopes: Vec::new(),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
            update_mask: vec![
                "revision.endpoint_generation".to_string(),
                "revision.client_base_path".to_string(),
                "revision.origin_prefix".to_string(),
                "revision.access_policy".to_string(),
            ],
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_UPDATE_GATEWAY_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::GatewayResponse>(
                    aos_proto_types::DELIVERY_SERVICE_UPDATE_GATEWAY_PATH,
                    &reviewed.gateway_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="subworkflow">
            <h4>"Stage gateway generation"</h4>
            <form class="stacked-form" on:submit=on_plan>
                <label><span>"Endpoint generation"</span><select required prop:value=move || endpoint_generation.get() on:change=move |event| endpoint_generation.set(event_target_value(&event))><Suspense fallback=move || view! { <option value=endpoint_generation.get_untracked()>"Loading endpoint generations…"</option> }>{move || Suspend::new(async move { match endpoint_generations.await.as_ref() { Ok(generations) => generations.iter().map(|generation| view! { <option value=generation.generation.to_string()>{format!("Generation {}{}", generation.generation, if generation.selected { " · selected" } else { "" })}</option> }).collect_view().into_any(), Err(_) => view! { <option value=endpoint_generation.get_untracked()>"Current pinned generation"</option> }.into_any() } })}</Suspense></select></label>
                <label><span>"Client base path"</span><input required prop:value=move || client_base_path.get() on:input=move |event| client_base_path.set(event_target_value(&event))/></label>
                <label><span>"Origin prefix"</span><input required prop:value=move || origin_prefix.get() on:input=move |event| origin_prefix.set(event_target_value(&event))/></label>
                <AccessPolicyFields signals=access/>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Review generation"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn GatewayGrants(client: ApiClient, gateway: aos_proto_types::Gateway) -> impl IntoView {
    let consumer_scope = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let gateway_id = gateway.stable_id.clone();
    let generation = gateway.desired_generation;
    let version = gateway.resource_version;
    let plan_client = client.clone();
    let row_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("gateway-grant");
        let request = gateway_grant_request(
            &gateway_id,
            generation,
            &consumer_scope.get_untracked(),
            &version,
            idempotency_key.clone(),
        );
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_GRANT_GATEWAY_SCOPE_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ConsumerScopeGrantResponse>(
                    aos_proto_types::DELIVERY_SERVICE_GRANT_GATEWAY_SCOPE_PATH,
                    &reviewed.consumer_grant_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="subworkflow">
            <h4>"Consumer scopes"</h4>
            <div class="compact-list">
                {gateway.grants.into_iter().filter(|grant| grant.state == "active").map(|grant| view! {
                    <GatewayGrantRow client=row_client.clone() grant=grant/>
                }).collect_view()}
            </div>
            <form class="stacked-form" on:submit=on_plan>
                <label><span>"Consumer scope key"</span><input required prop:value=move || consumer_scope.get() on:input=move |event| consumer_scope.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Review grant"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn GatewayGrantRow(client: ApiClient, grant: aos_proto_types::ConsumerScopeGrant) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let request_grant = grant.clone();
    let plan_client = client.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("gateway-revoke");
        let request = gateway_grant_request(
            &request_grant.resource_stable_id,
            request_grant.resource_generation,
            &request_grant.consumer_scope_key,
            &request_grant.resource_version,
            idempotency_key.clone(),
        );
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_REVOKE_GATEWAY_SCOPE_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ConsumerScopeGrantResponse>(
                    aos_proto_types::DELIVERY_SERVICE_REVOKE_GATEWAY_SCOPE_PATH,
                    &reviewed.consumer_grant_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="compact-list-row">
            <div><code>{grant.consumer_scope_key}</code><span>{format!("generation {} · {} live pins", grant.resource_generation, grant.live_pin_count)}</span></div>
            <button class="table-action" type="button" disabled=move || busy.get() on:click=on_plan>"Review revoke"</button>
        </div>
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
    }
}

#[component]
fn GatewayState(client: ApiClient, gateway: aos_proto_types::Gateway) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let enabling = !gateway.enabled;
    let stable_id = gateway.stable_id;
    let version = gateway.resource_version;
    let plan_client = client.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key(if enabling {
            "gateway-enable"
        } else {
            "gateway-disable"
        });
        let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
            stable_id: stable_id.clone(),
            expected_resource_version: Some(version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        let path = if enabling {
            aos_proto_types::DELIVERY_SERVICE_PLAN_ENABLE_GATEWAY_PATH
        } else {
            aos_proto_types::DELIVERY_SERVICE_PLAN_DISABLE_GATEWAY_PATH
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(path, &request)
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        let path = if enabling {
            aos_proto_types::DELIVERY_SERVICE_ENABLE_GATEWAY_PATH
        } else {
            aos_proto_types::DELIVERY_SERVICE_DISABLE_GATEWAY_PATH
        };
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::GatewayResponse>(path, &reviewed.delete_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="subworkflow">
            <h4>{if enabling { "Enable gateway" } else { "Disable gateway" }}</h4>
            <p>{if enabling { "Enable this generation for route use after review." } else { "Disable only after all live route pins have drained." }}</p>
            <button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_plan>{if enabling { "Review enable" } else { "Review disable" }}</button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn GatewayDelete(client: ApiClient, gateway: aos_proto_types::Gateway) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let stable_id = gateway.stable_id;
    let version = gateway.resource_version;
    let plan_client = client.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("gateway-delete");
        let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
            stable_id: stable_id.clone(),
            expected_resource_version: Some(version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_DELETE_GATEWAY_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                    aos_proto_types::DELIVERY_SERVICE_DELETE_GATEWAY_PATH,
                    &reviewed.delete_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="subworkflow danger-subworkflow">
            <h4>"Delete gateway"</h4>
            <p>"Deletion remains blocked while the gateway is enabled, granted, pinned, or referenced by routes."</p>
            <button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review deletion"</button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

fn gateway_revision(
    binding_id: &str,
    endpoint_id: &str,
    endpoint_generation: &str,
    client_base_path: &str,
    origin_prefix: &str,
    access: AccessPolicySignals,
) -> Result<aos_proto_types::GatewayRevisionSpec, String> {
    let endpoint_generation = endpoint_generation
        .parse::<i64>()
        .map_err(|_| "Endpoint generation must be a positive integer".to_string())?;
    if endpoint_generation <= 0 {
        return Err("Endpoint generation must be a positive integer".to_string());
    }
    Ok(aos_proto_types::GatewayRevisionSpec {
        binding_id: required(binding_id.to_string(), "Binding ID")?,
        endpoint_id: required(endpoint_id.to_string(), "Endpoint ID")?,
        endpoint_generation,
        client_base_path: canonical_path(client_base_path, "Client base path")?,
        origin_prefix: canonical_path(origin_prefix, "Origin prefix")?,
        access_policy: Some(access.build()?),
    })
}

fn gateway_grant_request(
    gateway_id: &str,
    generation: i64,
    consumer_scope: &str,
    version: &str,
    idempotency_key: String,
) -> aos_proto_types::PlanConsumerScopeGrantRequest {
    aos_proto_types::PlanConsumerScopeGrantRequest {
        resource_kind: "gateway".to_string(),
        resource_stable_id: gateway_id.to_string(),
        resource_generation: generation,
        consumer_scope_key: consumer_scope.trim().to_string(),
        expected_resource_version: version.to_string(),
        idempotency_key,
        pin_resolutions: Vec::new(),
    }
}

fn reload() {
    crate::app::refresh();
}
