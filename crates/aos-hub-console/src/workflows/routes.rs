//! Registry and cache delivery-route workflows.
//!
//! Routes pin exact endpoint, policy, and gateway generations. Hub proxy and
//! redirect routes own an access policy; direct routes inherit access and path
//! from their exact storage-gateway generation.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HelpTooltip, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{PendingPlan, idempotency_key, watch_draft};
use crate::route::{ConsoleRoute, ConsoleScope, route_selection_for_audience};
use crate::transport::ApiClient;

use super::access_policy::{
    AccessPolicyFields, AccessPolicySignals, access_policy_name, canonical_path,
};
use super::cache_integrations::CacheIntegrationWorkflow;
use super::delivery_workflow::DeliveryDestinationWorkflows;
use super::gateways::{endpoint_option_label, gateway_option_label};
use super::organization_scope::surface_authorization_scope;

/// Renders route workflows and delegates unrelated pages onward.
#[component]
pub(super) fn RouteWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Registry { path }, "delivery") => view! {
            <Routes client=client surface=registry_surface(path)/>
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "delivery") => view! {
            <Routes client=client surface=cache_surface(path)/>
        }
        .into_any(),
        _ => view! { <CacheIntegrationWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn Routes(client: ApiClient, surface: aos_proto_types::SurfaceRef) -> impl IntoView {
    let can_manage = client.allows("route.manage");
    let topology_client = client.clone();
    let topology_surface = surface.clone();
    let topology = LocalResource::new(move || {
        let client = topology_client.clone();
        let surface = topology_surface.clone();
        async move {
            client
                .call::<_, aos_proto_types::GetSurfaceTopologyResponse>(
                    aos_proto_types::TOPOLOGY_SERVICE_GET_SURFACE_TOPOLOGY_PATH,
                    &aos_proto_types::GetSurfaceTopologyRequest {
                        surface: Some(surface),
                    },
                )
                .await
        }
    });
    let choices_client = client.clone();
    let choices_surface = surface.clone();
    let choices_topology = topology;
    let choices = LocalResource::new(move || {
        let client = choices_client.clone();
        let surface = choices_surface.clone();
        async move {
            if !can_manage {
                return Ok(None);
            }
            let topology = choices_topology
                .await
                .as_ref()
                .map_err(ToString::to_string)?
                .clone();
            load_route_create_choices(&client, &surface, topology)
                .await
                .map(Some)
        }
    });
    let view_client = client.clone();
    let view_surface = surface.clone();

    view! {
        <div class="workflow-stack">
            <Suspense fallback=move || view! { <p class="loading-row">"Loading effective delivery…"</p> }>
                {move || {
                    let client = view_client.clone();
                    let surface = view_surface.clone();
                    Suspend::new(async move {
                        match topology.await.as_ref() {
                            Ok(response) => view! {
                                <DeliverySummary topology=response.clone()/>
                                <DeliveryDestinationWorkflows client=client.clone() surface=surface.clone() choices=choices can_manage=can_manage/>
                                <section class="panel resource-panel">
                                    <div class="section-heading"><div><p class="section-kicker">"Simultaneous delivery paths"</p><div class="section-title"><h2>"Routes"</h2><HelpTooltip term="Routes" summary="Multiple Hub-proxied, redirected, CDN-fronted, and direct routes can serve the same logical surface concurrently."/></div></div></div>
                                    {if response.routes.is_empty() {
                                        view! { <p class="muted">"No routes for this surface."</p> }.into_any()
                                    } else {
                                        view! { <div class="binding-list">{response.routes.iter().cloned().map(|route| view! { <RouteCard client=client.clone() surface=surface.clone() route=route choices=choices can_manage=can_manage/> }).collect_view()}</div> }.into_any()
                                    }}
                                </section>
                                <RouteAdvertisements client=client surface=surface canonical=response.route_advertisements.clone() routes=response.routes.clone() can_manage=can_manage/>
                            }.into_any(),
                            Err(failure) => view! { <section class="panel"><InlineError detail=failure.to_string()/></section> }.into_any(),
                        }
                    })
                }}
            </Suspense>
            {can_manage.then(|| view! { <RouteCreate client=client surface=surface choices=choices/> })}
        </div>
    }
}

#[component]
fn DeliverySummary(topology: aos_proto_types::GetSurfaceTopologyResponse) -> impl IntoView {
    let enabled = topology
        .routes
        .iter()
        .filter(|route| route.spec.as_ref().is_some_and(|spec| spec.enabled))
        .count();
    let healthy = topology
        .routes
        .iter()
        .filter(|route| {
            route.spec.as_ref().is_some_and(|spec| spec.enabled)
                && route
                    .observation
                    .as_ref()
                    .is_some_and(|observation| observation.state == "healthy")
        })
        .count();
    let audiences = topology.route_advertisements.len();
    let destinations = topology.route_advertisements.iter().map(|selection| {
        let route = topology.routes.iter().find(|route| route.stable_id == selection.route_id);
        let Some(route) = route else {
            return view! { <article class="revision-card"><h3>{selection.audience.clone()}</h3><p>"The selected route is unavailable. Inspect the audience selection below."</p></article> }.into_any();
        };
        let spec = route.spec.clone().unwrap_or_default();
        let endpoint = topology.canonical_endpoints.iter()
            .find(|endpoint| endpoint.stable_id == spec.endpoint_id);
        let target = target_name(&spec);
        let observation = route.observation.as_ref();
        let current = observation.is_some_and(|observed|
            observed.configuration_generation == route.configuration_generation
                && observed.configuration_digest == route.configuration_digest);
        let state = if !spec.enabled { "disabled" } else if !current { "awaiting observation" }
            else { observation.map(|value| value.state.as_str()).unwrap_or("unknown") };
        view! {
            <article class="revision-card">
                <div class="section-heading"><h3>{selection.audience.clone()}</h3><StatusBadge state=state.to_string() positive=state == "healthy"/></div>
                <div class="resource-identity">
                    <div><span>"Selected client URL"</span><code>{route.canonical_rendered_url.clone()}</code></div>
                    <div><span>"Access policy"</span><strong>{access_policy_name(spec.access_policy.as_ref())}</strong></div>
                    <div><span>"Storage target"</span><strong>{target}</strong></div>
                    <div><span>"Endpoint"</span><code>{format!("{} · generation {}", spec.endpoint_id, spec.endpoint_generation)}</code></div>
                    {endpoint.map(|endpoint| view! { <div><span>"Endpoint owner"</span><code>{endpoint.owner_scope_key.clone()}</code></div> })}
                </div>
                {observation.filter(|observed| current && !observed.error.is_empty()).map(|observed| view! { <p>{observed.error.clone()}</p> })}
            </article>
        }.into_any()
    }).collect_view();

    view! {
        <section class="panel delivery-summary" aria-labelledby="effective-delivery-title">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Effective configuration"</p>
                    <h2 id="effective-delivery-title">"Delivery at a glance"</h2>
                    <p>"See the URL selected for each client audience and the infrastructure behind it. Observed state is shown separately from the selection."</p>
                </div>
            </div>
            <div class="resource-identity">
                <div><span>"Enabled routes"</span><strong>{enabled}</strong></div>
                <div><span>"Healthy routes"</span><strong>{format!("{healthy} of {enabled}")}</strong></div>
                <div><span>"Audience defaults"</span><strong>{audiences}</strong></div>
                <div><span>"Storage placements"</span><strong>{topology.placements.len()}</strong></div>
            </div>
            <div class="binding-list">{destinations}</div>
            {(audiences == 0).then(|| view! { <p class="muted">"No audience has a selected destination. Add and verify delivery, then review activation."</p> })}
        </section>
    }
}

#[derive(Clone, Copy)]
struct RouteSignals {
    endpoint_id: RwSignal<String>,
    endpoint_generation: RwSignal<String>,
    base_path: RwSignal<String>,
    mode: RwSignal<String>,
    target_kind: RwSignal<String>,
    target_ref: RwSignal<String>,
    gateway_ref: RwSignal<String>,
    serves_git: RwSignal<bool>,
    serves_cache: RwSignal<bool>,
    serves_web: RwSignal<bool>,
    serves_oci: RwSignal<bool>,
    enabled: RwSignal<bool>,
    access: AccessPolicySignals,
}

#[derive(Clone, Debug)]
pub(super) struct RouteCreateChoices {
    pub(super) owner_scope_key: String,
    pub(super) endpoints: Vec<aos_proto_types::Endpoint>,
    pub(super) domains: Vec<aos_proto_types::Domain>,
    pub(super) placements: Vec<aos_proto_types::Placement>,
    pub(super) policies: Vec<aos_proto_types::PlacementPolicy>,
    pub(super) gateways: Vec<aos_proto_types::Gateway>,
    pub(super) boundaries: Vec<aos_proto_types::NetworkPolicy>,
}

impl RouteSignals {
    fn empty() -> Self {
        Self {
            endpoint_id: RwSignal::new(String::new()),
            endpoint_generation: RwSignal::new(String::new()),
            base_path: RwSignal::new("/".to_string()),
            mode: RwSignal::new("hub-proxy".to_string()),
            target_kind: RwSignal::new("placement".to_string()),
            target_ref: RwSignal::new(String::new()),
            gateway_ref: RwSignal::new(String::new()),
            serves_git: RwSignal::new(true),
            serves_cache: RwSignal::new(true),
            serves_web: RwSignal::new(true),
            serves_oci: RwSignal::new(false),
            enabled: RwSignal::new(false),
            access: AccessPolicySignals::public(),
        }
    }

    fn from_spec(spec: &aos_proto_types::RouteSpec) -> Self {
        use aos_proto_types::route_target::Target;
        let mut signals = Self::empty();
        signals.endpoint_id.set(spec.endpoint_id.clone());
        signals
            .endpoint_generation
            .set(spec.endpoint_generation.to_string());
        signals.base_path.set(spec.base_path.clone());
        signals.access = AccessPolicySignals::from_policy(spec.access_policy.clone());
        signals.enabled.set(spec.enabled);
        if let Some(capabilities) = spec.capabilities.as_ref() {
            signals.serves_git.set(capabilities.serves_git);
            signals.serves_cache.set(capabilities.serves_cache);
            signals.serves_web.set(capabilities.serves_web);
            signals.serves_oci.set(capabilities.serves_oci);
        }
        match spec.target.as_ref().and_then(|value| value.target.as_ref()) {
            Some(Target::HubPlacement(value)) => {
                signals.mode.set(hub_mode(value.delivery_kind).to_string());
                signals.target_kind.set("placement".to_string());
                signals.target_ref.set(value.placement_name.clone());
            }
            Some(Target::HubPolicyRevision(value)) => {
                signals.mode.set(hub_mode(value.delivery_kind).to_string());
                signals.target_kind.set("policy".to_string());
                signals
                    .target_ref
                    .set(format!("{}@{}", value.policy_name, value.revision));
            }
            Some(Target::DirectGatewayPlacement(value)) => {
                signals.mode.set("direct".to_string());
                signals.target_kind.set("placement".to_string());
                signals.target_ref.set(value.placement_name.clone());
                signals
                    .gateway_ref
                    .set(format!("{}@{}", value.gateway_id, value.gateway_generation));
            }
            None => {}
        }
        signals
    }

    fn draft_key(self) -> String {
        [
            self.endpoint_id.get(),
            self.endpoint_generation.get(),
            self.base_path.get(),
            self.mode.get(),
            self.target_kind.get(),
            self.target_ref.get(),
            self.gateway_ref.get(),
            self.serves_git.get().to_string(),
            self.serves_cache.get().to_string(),
            self.serves_web.get().to_string(),
            self.serves_oci.get().to_string(),
            self.enabled.get().to_string(),
            self.access.draft_key(),
        ]
        .join("\u{1f}")
    }
}

#[component]
fn RouteFields(
    signals: RouteSignals,
    immutable_identity: bool,
    choices: RouteCreateChoices,
) -> impl IntoView {
    let endpoints = choices.endpoints.clone();
    let selected_endpoints = choices.endpoints;
    let placements = choices.placements.clone();
    let policies = choices.policies.clone();
    let selected_placements = choices.placements;
    let selected_policies = choices.policies;
    let gateways = choices.gateways;
    let boundaries = choices.boundaries;
    let on_endpoint_change = move |event| {
        let value = event_target_value(&event);
        signals.endpoint_id.set(value.clone());
        let generation = selected_endpoints
            .iter()
            .find(|endpoint| endpoint.stable_id == value)
            .map(|endpoint| endpoint.desired_generation)
            .unwrap_or_default();
        signals.endpoint_generation.set(generation.to_string());
    };
    let on_target_kind_change = Callback::new(move |value: String| {
        signals.target_kind.set(value.clone());
        let target = if value == "policy" {
            selected_policies
                .first()
                .map(|policy| format!("{}@{}", policy.name, policy.current_revision))
        } else {
            selected_placements
                .first()
                .map(|placement| placement.name.clone())
        };
        signals.target_ref.set(target.unwrap_or_default());
    });
    view! {
        {if immutable_identity { view! { <label><span>"Endpoint"</span><select disabled aria-disabled="true" prop:value=move || signals.endpoint_id.get()>{endpoints.iter().map(|endpoint| view! { <option value=endpoint.stable_id.clone()>{endpoint_option_label(endpoint)}</option> }).collect_view()}</select></label> }.into_any() } else { view! { <label><span>"Endpoint"</span><select required prop:value=move || signals.endpoint_id.get() on:change=on_endpoint_change>{endpoints.iter().map(|endpoint| view! { <option value=endpoint.stable_id.clone()>{endpoint_option_label(endpoint)}</option> }).collect_view()}</select></label><label><span>"Base path"</span><input required prop:value=move || signals.base_path.get() on:input=move |event| signals.base_path.set(event_target_value(&event))/></label> }.into_any() }}
        <label><span>"Endpoint generation"</span><select required prop:value=move || signals.endpoint_generation.get() on:change=move |event| signals.endpoint_generation.set(event_target_value(&event))>{endpoints.iter().filter(|endpoint| endpoint.stable_id == signals.endpoint_id.get_untracked()).map(|endpoint| view! { <option value=endpoint.desired_generation.to_string()>{format!("Current generation {}", endpoint.desired_generation)}</option> }).collect_view()}<option value=signals.endpoint_generation.get_untracked()>{format!("Pinned generation {}", signals.endpoint_generation.get_untracked())}</option></select></label>
        <label><span>"Delivery mode"</span><select prop:value=move || signals.mode.get() on:change=move |event| signals.mode.set(event_target_value(&event))><option value="hub-proxy">"Hub proxy"</option><option value="hub-redirect">"Hub redirect"</option><option value="direct">"Direct gateway"</option></select></label>
        {move || if signals.mode.get() == "direct" { view! { <label><span>"Placement"</span><select required prop:value=move || signals.target_ref.get() on:change=move |event| signals.target_ref.set(event_target_value(&event))>{placements.iter().map(|placement| view! { <option value=placement.name.clone()>{format!("{} · {}", placement.name, placement.binding_name)}</option> }).collect_view()}</select></label><label><span>"Gateway"</span><select required prop:value=move || signals.gateway_ref.get() on:change=move |event| signals.gateway_ref.set(event_target_value(&event))>{gateways.iter().map(|gateway| view! { <option value=format!("{}@{}", gateway.stable_id, gateway.desired_generation)>{gateway_option_label(gateway)}</option> }).collect_view()}</select></label> }.into_any() } else { let boundaries = boundaries.clone(); let on_target_kind_change = on_target_kind_change.clone(); let policies = policies.clone(); let placements = placements.clone(); view! { <label><span>"Target kind"</span><select prop:value=move || signals.target_kind.get() on:change=move |event| on_target_kind_change.run(event_target_value(&event))><option value="placement">"Placement"</option><option value="policy">"Placement policy revision"</option></select></label>{move || { let policies = policies.clone(); let placements = placements.clone(); if signals.target_kind.get() == "policy" { view! { <label><span>"Placement policy"</span><select required prop:value=move || signals.target_ref.get() on:change=move |event| signals.target_ref.set(event_target_value(&event))>{policies.iter().map(|policy| view! { <option value=format!("{}@{}", policy.name, policy.current_revision)>{format!("{} · revision {}", policy.name, policy.current_revision)}</option> }).collect_view()}</select></label> }.into_any() } else { view! { <label><span>"Placement"</span><select required prop:value=move || signals.target_ref.get() on:change=move |event| signals.target_ref.set(event_target_value(&event))>{placements.iter().map(|placement| view! { <option value=placement.name.clone()>{format!("{} · {}", placement.name, placement.binding_name)}</option> }).collect_view()}</select></label> }.into_any() }}}<AccessPolicyFields signals=signals.access allow_hub_auth=true boundaries=boundaries/> }.into_any() }}
        <label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_git.get() on:change=move |event| signals.serves_git.set(event_target_checked(&event))/><span>"Serve Git"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_cache.get() on:change=move |event| signals.serves_cache.set(event_target_checked(&event))/><span>"Serve Nix cache"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_web.get() on:change=move |event| signals.serves_web.set(event_target_checked(&event))/><span>"Serve Web"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_oci.get() on:change=move |event| signals.serves_oci.set(event_target_checked(&event))/><span>"Serve OCI"</span></label>
    }
}

#[component]
fn RouteCreate(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    choices: LocalResource<Result<Option<RouteCreateChoices>, String>>,
) -> impl IntoView {
    view! {
        <Suspense fallback=move || view! { <section class="panel editor-panel"><p class="loading-row">"Loading endpoints, placements, and gateways…"</p></section> }>
            {move || {
                let client = client.clone();
                let surface = surface.clone();
                Suspend::new(async move {
                    match choices.await.as_ref() {
                        Ok(Some(choices)) => view! { <RouteCreateForm client=client surface=surface choices=choices.clone()/> }.into_any(),
                        Ok(None) => ().into_any(),
                        Err(detail) => view! { <section class="panel editor-panel"><InlineError detail=detail.clone()/></section> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

async fn load_route_create_choices(
    client: &ApiClient,
    surface: &aos_proto_types::SurfaceRef,
    topology: aos_proto_types::GetSurfaceTopologyResponse,
) -> Result<RouteCreateChoices, String> {
    let (owner_scope_key, _) = surface_authorization_scope(client, surface).await?;
    let endpoint_scope = owner_scope_key.clone();
    let endpoints = client.collect_pages::<_, aos_proto_types::ListEndpointsResponse, _, _, _>(
        aos_proto_types::DELIVERY_SERVICE_LIST_ENDPOINTS_PATH,
        move |page_token| aos_proto_types::ListTopologyResourcesRequest {
            owner_scope_key: endpoint_scope.clone(),
            page_size: 100,
            page_token,
            include_granted: true,
        },
        |response| (response.endpoints, response.next_page_token),
    );
    let boundary_scope = owner_scope_key.clone();
    let boundaries = client
        .collect_pages::<_, aos_proto_types::ListNetworkPoliciesResponse, _, _, _>(
            aos_proto_types::NETWORK_POLICY_SERVICE_LIST_NETWORK_POLICIES_PATH,
            move |page_token| aos_proto_types::ListTopologyResourcesRequest {
                owner_scope_key: boundary_scope.clone(),
                page_size: 100,
                page_token,
                include_granted: true,
            },
            |response| (response.network_policies, response.next_page_token),
        );
    let domain_scope = owner_scope_key.clone();
    let domains = client.collect_pages::<_, aos_proto_types::ListDomainsResponse, _, _, _>(
        aos_proto_types::DOMAIN_SERVICE_LIST_DOMAINS_PATH,
        move |page_token| aos_proto_types::ListDomainsRequest {
            owner_scope_key: domain_scope.clone(),
            page_size: 100,
            page_token,
        },
        |response| (response.domains, response.next_page_token),
    );
    let gateway_scope = owner_scope_key.clone();
    let gateways = client.collect_pages::<_, aos_proto_types::ListGatewaysResponse, _, _, _>(
        aos_proto_types::DELIVERY_SERVICE_LIST_GATEWAYS_PATH,
        move |page_token| aos_proto_types::ListGatewaysRequest {
            binding: None,
            page_size: 100,
            page_token,
            owner_scope_key: gateway_scope.clone(),
            include_granted: true,
        },
        |response| (response.gateways, response.next_page_token),
    );
    let (endpoints, boundaries, domains, gateways) =
        futures::join!(endpoints, boundaries, domains, gateways);
    let endpoints = endpoints.map_err(|failure| failure.to_string())?;
    let boundaries = boundaries.map_err(|failure| failure.to_string())?;
    let domains = domains.map_err(|failure| failure.to_string())?;
    let gateways = gateways.map_err(|failure| failure.to_string())?;

    Ok(RouteCreateChoices {
        owner_scope_key,
        endpoints,
        domains,
        placements: topology.placements,
        policies: topology.placement_policies,
        gateways,
        boundaries,
    })
}

#[component]
fn RouteCreateForm(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    choices: RouteCreateChoices,
) -> impl IntoView {
    let stable_id = RwSignal::new(String::new());
    let signals = RouteSignals::empty();
    if let Some(endpoint) = choices.endpoints.first() {
        signals.endpoint_id.set(endpoint.stable_id.clone());
        signals
            .endpoint_generation
            .set(endpoint.desired_generation.to_string());
    }
    if let Some(placement) = choices.placements.first() {
        signals.target_ref.set(placement.name.clone());
    }
    if let Some(gateway) = choices.gateways.first() {
        signals.gateway_ref.set(format!(
            "{}@{}",
            gateway.stable_id, gateway.desired_generation
        ));
    }
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = stable_id.get();
            let _ = signals.draft_key();
        },
        pending,
        error,
    );
    let endpoint_choices = choices.endpoints.clone();
    let selected_endpoints = choices.endpoints;
    let direct_placement_choices = choices.placements.clone();
    let hub_placement_choices = choices.placements;
    let policy_choices = choices.policies.clone();
    let selected_placements = hub_placement_choices.clone();
    let selected_policies = choices.policies;
    let gateway_choices = choices.gateways.clone();
    let selected_gateways = choices.gateways;
    let boundaries = choices.boundaries;
    let on_endpoint_change = move |event| {
        let value = event_target_value(&event);
        signals.endpoint_id.set(value.clone());
        let generation = selected_endpoints
            .iter()
            .find(|endpoint| endpoint.stable_id == value)
            .map(|endpoint| endpoint.desired_generation)
            .unwrap_or_default();
        signals.endpoint_generation.set(generation.to_string());
        if let Some(gateway) = selected_gateways.iter().find(|gateway| {
            gateway.desired.as_ref().is_some_and(|revision| {
                revision.endpoint_id == value && revision.endpoint_generation == generation
            })
        }) {
            signals.gateway_ref.set(format!(
                "{}@{}",
                gateway.stable_id, gateway.desired_generation
            ));
        }
    };
    let on_target_kind_change = Callback::new(move |value: String| {
        signals.target_kind.set(value.clone());
        let target = if value == "policy" {
            selected_policies
                .first()
                .map(|policy| format!("{}@{}", policy.name, policy.current_revision))
        } else {
            selected_placements
                .first()
                .map(|placement| placement.name.clone())
        };
        signals.target_ref.set(target.unwrap_or_default());
    });
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let spec = match build_spec(surface.clone(), signals) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let idempotency_key = idempotency_key("route-create");
        let request = aos_proto_types::PlanRouteMutationRequest {
            stable_id: stable_id.get_untracked().trim().to_string(),
            spec: Some(spec),
            expected_resource_version: String::new(),
            idempotency_key: idempotency_key.clone(),
            update_mask: Vec::new(),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::ROUTE_SERVICE_PLAN_CREATE_ROUTE_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
            Some(draft_epoch),
        );
    };
    let on_apply = apply_route(
        client,
        aos_proto_types::ROUTE_SERVICE_CREATE_ROUTE_PATH,
        pending,
        error,
        busy,
    );
    view! { <section class="panel editor-panel"><div class="section-heading"><div><p class="section-kicker">"Guided setup"</p><h2>"Create route"</h2><p>"Choose named topology resources; exact stable IDs and generations are pinned automatically."</p></div></div><form class="editor-form" on:submit=on_plan><label><span>"Route name"</span><input prop:value=move || stable_id.get() on:input=move |event| stable_id.set(event_target_value(&event))/></label><label><span>"Endpoint"</span><select required prop:value=move || signals.endpoint_id.get() on:change=on_endpoint_change>{endpoint_choices.iter().map(|endpoint| view! { <option value=endpoint.stable_id.clone()>{endpoint_option_label(endpoint)}</option> }).collect_view()}</select>{endpoint_choices.is_empty().then(|| view! { <small>"No endpoints are available in this surface's owner scope."</small> })}</label><label><span>"Endpoint generation"</span><input readonly aria-readonly="true" prop:value=move || signals.endpoint_generation.get()/></label><label><span>"Base path"</span><input required prop:value=move || signals.base_path.get() on:input=move |event| signals.base_path.set(event_target_value(&event))/></label><label><span>"Delivery mode"</span><select prop:value=move || signals.mode.get() on:change=move |event| signals.mode.set(event_target_value(&event))><option value="hub-proxy">"Hub proxy"</option><option value="hub-redirect">"Hub redirect"</option><option value="direct">"Direct gateway"</option></select></label>{move || if signals.mode.get() == "direct" { view! { <label><span>"Placement"</span><select required prop:value=move || signals.target_ref.get() on:change=move |event| signals.target_ref.set(event_target_value(&event))>{direct_placement_choices.iter().map(|placement| view! { <option value=placement.name.clone()>{format!("{} · {}", placement.name, placement.binding_name)}</option> }).collect_view()}</select></label><label><span>"Gateway"</span><select required prop:value=move || signals.gateway_ref.get() on:change=move |event| signals.gateway_ref.set(event_target_value(&event))>{gateway_choices.iter().map(|gateway| view! { <option value=format!("{}@{}", gateway.stable_id, gateway.desired_generation)>{gateway_option_label(gateway)}</option> }).collect_view()}</select>{gateway_choices.is_empty().then(|| view! { <small>"No gateways are available. Create one from Settings or the owning organization first."</small> })}</label> }.into_any() } else { let on_target_kind_change = on_target_kind_change.clone(); let policy_choices = policy_choices.clone(); let hub_placement_choices = hub_placement_choices.clone(); let boundaries = boundaries.clone(); view! { <label><span>"Target kind"</span><select prop:value=move || signals.target_kind.get() on:change=move |event| on_target_kind_change.run(event_target_value(&event))><option value="placement">"Placement"</option><option value="policy">"Placement policy revision"</option></select></label>{move || { let policy_choices = policy_choices.clone(); let hub_placement_choices = hub_placement_choices.clone(); if signals.target_kind.get() == "policy" { view! { <label><span>"Placement policy"</span><select required prop:value=move || signals.target_ref.get() on:change=move |event| signals.target_ref.set(event_target_value(&event))>{policy_choices.iter().map(|policy| view! { <option value=format!("{}@{}", policy.name, policy.current_revision)>{format!("{} · revision {}", policy.name, policy.current_revision)}</option> }).collect_view()}</select></label> }.into_any() } else { view! { <label><span>"Placement"</span><select required prop:value=move || signals.target_ref.get() on:change=move |event| signals.target_ref.set(event_target_value(&event))>{hub_placement_choices.iter().map(|placement| view! { <option value=placement.name.clone()>{format!("{} · {}", placement.name, placement.binding_name)}</option> }).collect_view()}</select></label> }.into_any() }}}<AccessPolicyFields signals=signals.access allow_hub_auth=true boundaries=boundaries/> }.into_any() }}<label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_git.get() on:change=move |event| signals.serves_git.set(event_target_checked(&event))/><span>"Serve Git"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_cache.get() on:change=move |event| signals.serves_cache.set(event_target_checked(&event))/><span>"Serve Nix cache"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_web.get() on:change=move |event| signals.serves_web.set(event_target_checked(&event))/><span>"Serve Web"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_oci.get() on:change=move |event| signals.serves_oci.set(event_target_checked(&event))/><span>"Serve OCI"</span></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get() || signals.endpoint_id.get().is_empty() || signals.target_ref.get().is_empty()>"Review route"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

#[component]
fn RouteCard(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    route: aos_proto_types::Route,
    choices: LocalResource<Result<Option<RouteCreateChoices>, String>>,
    can_manage: bool,
) -> impl IntoView {
    let spec = route.spec.clone().unwrap_or_default();
    let observation = route.observation.clone().unwrap_or_default();
    let mode = route_mode(&spec);
    view! {
        <details class="binding-card">
            <summary><div><span class="resource-kind">{mode}</span><h3>{route.canonical_rendered_url.clone()}</h3><code>{route.stable_id.clone()}</code></div><StatusBadge state=observation.state.clone() positive=observation.state == "healthy"/></summary>
            <div class="binding-details">
                <div class="topology-path" aria-label="Effective route topology">
                    <span><small>"Endpoint"</small><code>{format!("{}@{}", spec.endpoint_id, spec.endpoint_generation)}</code></span>
                    <b aria-hidden="true">"→"</b>
                    <span><small>"Target"</small><code>{target_name(&spec)}</code></span>
                    <b aria-hidden="true">"→"</b>
                    <span><small>"Public URL"</small><code>{route.canonical_rendered_url.clone()}</code></span>
                </div>
                <div class="resource-identity"><div><span>"Access"</span><strong>{access_policy_name(spec.access_policy.as_ref())}</strong></div><div><span>"Configuration generation"</span><strong>{route.configuration_generation}</strong></div><div><span>"Observed generation"</span><strong>{observation.configuration_generation}</strong></div><div><span>"Version"</span><code>{route.resource_version.clone()}</code></div></div>
                {(!observation.error.is_empty()).then(|| view! { <InlineError detail=observation.error/> })}
                <RouteExplain client=client.clone() route=route.clone()/>
                {can_manage.then(|| view! {
                    <details class="advanced-controls">
                        <summary>"Advanced route controls"</summary>
                        <Suspense fallback=move || view! { <p class="loading-row">"Loading route controls…"</p> }>
                            {move || {
                                let client = client.clone();
                                let surface = surface.clone();
                                let route = route.clone();
                                Suspend::new(async move {
                                    match choices.await.as_ref() {
                                        Ok(Some(choices)) => view! {
                                            <div class="subworkflow-grid"><RouteUpdate client=client.clone() surface=surface.clone() route=route.clone() choices=choices.clone()/><RouteLifecycle client=client.clone() route=route.clone()/></div>
                                            <RouteReplace client=client surface=surface route=route choices=choices.clone()/>
                                        }.into_any(),
                                        Ok(None) => ().into_any(),
                                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                                    }
                                })
                            }}
                        </Suspense>
                    </details>
                })}
            </div>
        </details>
    }
}

#[component]
fn RouteUpdate(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    route: aos_proto_types::Route,
    choices: RouteCreateChoices,
) -> impl IntoView {
    let signals = RouteSignals::from_spec(&route.spec.clone().unwrap_or_default());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = signals.draft_key();
        },
        pending,
        error,
    );
    let route_id = route.stable_id;
    let version = route.resource_version;
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let spec = match build_spec(surface.clone(), signals) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let idempotency_key = idempotency_key("route-update");
        let request = aos_proto_types::PlanRouteMutationRequest {
            stable_id: route_id.clone(),
            spec: Some(spec),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
            update_mask: vec![
                "spec.endpoint_generation".to_string(),
                "spec.target".to_string(),
                "spec.access_policy".to_string(),
                "spec.capabilities".to_string(),
            ],
        };
        plan(
            plan_client.clone(),
            aos_proto_types::ROUTE_SERVICE_PLAN_UPDATE_ROUTE_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
            Some(draft_epoch),
        );
    };
    let on_apply = apply_route(
        client,
        aos_proto_types::ROUTE_SERVICE_UPDATE_ROUTE_PATH,
        pending,
        error,
        busy,
    );
    view! { <section class="subworkflow"><h4>"Update route generation"</h4><form class="stacked-form" on:submit=on_plan><RouteFields signals=signals immutable_identity=true choices=choices/><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review update"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

#[component]
fn RouteLifecycle(client: ApiClient, route: aos_proto_types::Route) -> impl IntoView {
    let enabled = route.spec.as_ref().is_some_and(|value| value.enabled);
    let action = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let route_id = route.stable_id;
    let version = route.resource_version;
    let on_action = Callback::new(move |selected: &'static str| {
        action.set(selected.to_string());
        let idempotency_key = idempotency_key(&format!("route-{selected}"));
        let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
            stable_id: route_id.clone(),
            expected_resource_version: Some(version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        let path = match selected {
            "enable" => aos_proto_types::ROUTE_SERVICE_PLAN_ENABLE_ROUTE_PATH,
            "disable" => aos_proto_types::ROUTE_SERVICE_PLAN_DISABLE_ROUTE_PATH,
            "delete" => aos_proto_types::ROUTE_SERVICE_PLAN_DELETE_ROUTE_PATH,
            _ => return,
        };
        plan(
            plan_client.clone(),
            path,
            request,
            idempotency_key,
            pending,
            error,
            busy,
            None,
        );
    });
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let path = match action.get_untracked().as_str() {
            "enable" => aos_proto_types::ROUTE_SERVICE_ENABLE_ROUTE_PATH,
            "disable" => aos_proto_types::ROUTE_SERVICE_DISABLE_ROUTE_PATH,
            "delete" => aos_proto_types::ROUTE_SERVICE_DELETE_ROUTE_PATH,
            _ => return,
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, serde_json::Value>(path, &reviewed.delete_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    let state_action = on_action.clone();
    let state = move |_| state_action.run(if enabled { "disable" } else { "enable" });
    let delete = move |_| on_action.run("delete");
    view! { <section class="subworkflow"><h4>"Lifecycle"</h4><div class="form-actions"><button class="secondary-button" type="button" disabled=move || busy.get() on:click=state>{if enabled { "Review disable" } else { "Review enable" }}</button><button class="danger-button" type="button" disabled=move || busy.get() on:click=delete>"Review deletion"</button></div><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

#[component]
fn RouteExplain(client: ApiClient, route: aos_proto_types::Route) -> impl IntoView {
    let path = RwSignal::new("/".to_string());
    let access_class = RwSignal::new("web".to_string());
    let result = RwSignal::new(None::<aos_proto_types::ExplainRouteResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let route_id = route.stable_id;
    let on_explain = move |event: SubmitEvent| {
        event.prevent_default();
        let client = client.clone();
        let request = aos_proto_types::ExplainRouteRequest {
            route_id: route_id.clone(),
            machine_path: path.get_untracked(),
            access_class: access_class.get_untracked(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ExplainRouteResponse>(
                    aos_proto_types::ROUTE_SERVICE_EXPLAIN_ROUTE_PATH,
                    &request,
                )
                .await
            {
                Ok(response) => result.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    view! { <section class="subworkflow"><h4>"Explain request"</h4><form class="editor-form" on:submit=on_explain><label><span>"Machine path"</span><input required prop:value=move || path.get() on:input=move |event| path.set(event_target_value(&event))/></label><label><span>"Capability"</span><select prop:value=move || access_class.get() on:change=move |event| access_class.set(event_target_value(&event))><option value="git">"Git"</option><option value="nix_cache">"Nix cache"</option><option value="web">"Web"</option></select></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Explain"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || result.get().map(|value| view! { <div class="resource-identity"><div><span>"Normalized URL"</span><code>{value.normalized_url}</code></div><div><span>"Decisions"</span><span>{value.decisions.join(" · ")}</span></div><div><span>"Rejections"</span><span>{value.rejection_reasons.join(" · ")}</span></div></div> })}</section> }
}

#[component]
fn RouteReplace(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    route: aos_proto_types::Route,
    choices: RouteCreateChoices,
) -> impl IntoView {
    let successor_id = RwSignal::new(String::new());
    let signals = RouteSignals::from_spec(&route.spec.clone().unwrap_or_default());
    signals.enabled.set(false);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = successor_id.get();
            let _ = signals.draft_key();
        },
        pending,
        error,
    );
    let predecessor_id = route.stable_id;
    let version = route.resource_version;
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let spec = match build_spec(surface.clone(), signals) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let idempotency_key = idempotency_key("route-replace");
        let request = aos_proto_types::PlanReplaceRouteRequest {
            predecessor_route_id: predecessor_id.clone(),
            stable_id: successor_id.get_untracked().trim().to_string(),
            spec: Some(spec),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::ROUTE_SERVICE_PLAN_REPLACE_ROUTE_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
            Some(draft_epoch),
        );
    };
    let on_apply = apply_route(
        client,
        aos_proto_types::ROUTE_SERVICE_REPLACE_ROUTE_PATH,
        pending,
        error,
        busy,
    );
    view! { <section class="subworkflow danger-subworkflow"><h4>"Replace route identity"</h4><p>"Endpoint or URL-path identity changes create a distinct disabled successor; they never mutate the live route in place."</p><form class="editor-form" on:submit=on_plan><label><span>"Successor name"</span><input prop:value=move || successor_id.get() on:input=move |event| successor_id.set(event_target_value(&event))/></label><RouteFields signals=signals immutable_identity=false choices=choices/><button class="danger-button" type="submit" disabled=move || busy.get()>"Review replacement"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

#[component]
fn RouteAdvertisements(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    canonical: Vec<aos_proto_types::RouteAdvertisement>,
    routes: Vec<aos_proto_types::Route>,
    can_manage: bool,
) -> impl IntoView {
    // Keep the initial signal aligned with the first server-rendered option.
    // Otherwise hydration displays Git while submissions retain Web until the
    // user changes the select to a different value and back.
    let audience = RwSignal::new("git".to_string());
    let enabled_route_ids = routes
        .iter()
        .filter(|value| value.spec.as_ref().is_some_and(|spec| spec.enabled))
        .map(|value| value.stable_id.clone())
        .collect::<Vec<_>>();
    let advertisement_choices = canonical
        .iter()
        .map(|value| (value.audience.clone(), value.route_id.clone()))
        .collect::<Vec<_>>();
    let initial_route =
        route_selection_for_audience("git", &advertisement_choices, &enabled_route_ids);
    let route_id = RwSignal::new(initial_route);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = audience.get();
            let _ = route_id.get();
        },
        pending,
        error,
    );
    let request_canonical = canonical.clone();
    let selected_advertisements = advertisement_choices;
    let selected_enabled_routes = enabled_route_ids;
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let selected_audience = audience.get_untracked();
        let expected_resource_version = request_canonical
            .iter()
            .find(|value| value.audience == selected_audience)
            .map(|value| value.resource_version.clone())
            .unwrap_or_default();
        let idempotency_key = idempotency_key("canonical-route-set");
        let request = aos_proto_types::PlanRouteAdvertisementRequest {
            surface: Some(surface.clone()),
            audience: selected_audience,
            route_id: route_id.get_untracked(),
            expected_resource_version,
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::ROUTE_SERVICE_PLAN_SET_ROUTE_ADVERTISEMENT_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
            Some(draft_epoch),
        );
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RouteAdvertisementResponse>(
                    aos_proto_types::ROUTE_SERVICE_SET_ROUTE_ADVERTISEMENT_PATH,
                    &reviewed.route_advertisement_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    view! { <section class="panel editor-panel"><div class="section-heading"><div><p class="section-kicker">"Audience defaults"</p><div class="section-title"><h2>"Route advertisements"</h2><HelpTooltip term="Route advertisements" summary="Each audience resolves to one enabled route while alternate routes remain simultaneously available."/></div></div></div><div class="compact-list">{canonical.into_iter().map(|value| view! { <div class="compact-list-row"><div><strong>{value.audience}</strong><code>{value.route_id}</code></div></div> }).collect_view()}</div>{can_manage.then(|| view! { <form class="editor-form" on:submit=on_plan><label><span>"Audience"</span><select prop:value=move || audience.get() on:change=move |event| { let selected = event_target_value(&event); audience.set(selected.clone()); route_id.set(route_selection_for_audience(&selected, &selected_advertisements, &selected_enabled_routes)); }><option value="git">"Git"</option><option value="nix_cache">"Nix cache"</option><option value="web">"Web"</option></select></label><label><span>"Enabled route"</span><select prop:value=move || route_id.get() on:change=move |event| route_id.set(event_target_value(&event))>{routes.iter().filter(|route| route.spec.as_ref().is_some_and(|spec| spec.enabled)).map(|route| view! { <option value=route.stable_id.clone()>{route.canonical_rendered_url.clone()}</option> }).collect_view()}</select></label><div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review canonical selection"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/> })}</section> }
}

fn build_spec(
    surface: aos_proto_types::SurfaceRef,
    signals: RouteSignals,
) -> Result<aos_proto_types::RouteSpec, String> {
    use aos_proto_types::route_target::Target;
    let endpoint_generation = positive_generation(
        &signals.endpoint_generation.get_untracked(),
        "Endpoint generation",
    )?;
    let endpoint_id = required(&signals.endpoint_id.get_untracked(), "Endpoint stable ID")?;
    let capabilities = aos_proto_types::RouteCapabilities {
        serves_git: signals.serves_git.get_untracked(),
        serves_cache: signals.serves_cache.get_untracked(),
        serves_web: signals.serves_web.get_untracked(),
        serves_oci: signals.serves_oci.get_untracked(),
    };
    if !capabilities.serves_git
        && !capabilities.serves_cache
        && !capabilities.serves_web
        && !capabilities.serves_oci
    {
        return Err("Select at least one served capability".to_string());
    }
    let mode = signals.mode.get_untracked();
    let (base_path, target, access_policy) = if mode == "direct" {
        let (gateway_id, gateway_generation) =
            generation_ref(&signals.gateway_ref.get_untracked(), "Gateway")?;
        (
            String::new(),
            Target::DirectGatewayPlacement(aos_proto_types::DirectGatewayPlacementTarget {
                placement_name: required(&signals.target_ref.get_untracked(), "Placement")?,
                gateway_id,
                gateway_generation,
            }),
            None,
        )
    } else {
        let delivery_kind = match mode.as_str() {
            "hub-proxy" => aos_proto_types::HubDeliveryKind::Proxy as i32,
            "hub-redirect" => aos_proto_types::HubDeliveryKind::Redirect as i32,
            _ => return Err("Unsupported route mode".to_string()),
        };
        let target = if signals.target_kind.get_untracked() == "policy" {
            let (policy_name, revision) =
                generation_ref(&signals.target_ref.get_untracked(), "Placement policy")?;
            Target::HubPolicyRevision(aos_proto_types::HubPolicyRevisionTarget {
                policy_name,
                revision,
                delivery_kind,
            })
        } else {
            Target::HubPlacement(aos_proto_types::HubPlacementTarget {
                placement_name: required(&signals.target_ref.get_untracked(), "Placement")?,
                delivery_kind,
            })
        };
        (
            canonical_path(&signals.base_path.get_untracked(), "Base path")?,
            target,
            Some(signals.access.build_for_route()?),
        )
    };
    Ok(aos_proto_types::RouteSpec {
        surface: Some(surface),
        endpoint_id,
        endpoint_generation,
        base_path,
        target: Some(aos_proto_types::RouteTarget {
            target: Some(target),
        }),
        access_policy,
        capabilities: Some(capabilities),
        enabled: signals.enabled.get_untracked(),
    })
}

fn route_mode(spec: &aos_proto_types::RouteSpec) -> &'static str {
    use aos_proto_types::route_target::Target;
    match spec.target.as_ref().and_then(|value| value.target.as_ref()) {
        Some(Target::DirectGatewayPlacement(_)) => "direct",
        Some(Target::HubPlacement(value)) => hub_mode(value.delivery_kind),
        Some(Target::HubPolicyRevision(value)) => hub_mode(value.delivery_kind),
        None => "unknown",
    }
}
fn hub_mode(kind: i32) -> &'static str {
    match aos_proto_types::HubDeliveryKind::try_from(kind)
        .unwrap_or(aos_proto_types::HubDeliveryKind::Unspecified)
    {
        aos_proto_types::HubDeliveryKind::Proxy => "hub-proxy",
        aos_proto_types::HubDeliveryKind::Redirect => "hub-redirect",
        aos_proto_types::HubDeliveryKind::Unspecified => "unknown",
    }
}
fn target_name(spec: &aos_proto_types::RouteSpec) -> String {
    use aos_proto_types::route_target::Target;
    match spec.target.as_ref().and_then(|value| value.target.as_ref()) {
        Some(Target::HubPlacement(value)) => value.placement_name.clone(),
        Some(Target::HubPolicyRevision(value)) => {
            format!("{}@{}", value.policy_name, value.revision)
        }
        Some(Target::DirectGatewayPlacement(value)) => format!(
            "{} via {}@{}",
            value.placement_name, value.gateway_id, value.gateway_generation
        ),
        None => "unknown".to_string(),
    }
}
fn generation_ref(value: &str, field: &str) -> Result<(String, i64), String> {
    let (id, generation) = value
        .trim()
        .rsplit_once('@')
        .ok_or_else(|| format!("{field} uses stable-id@generation"))?;
    let generation = positive_generation(generation, field)?;
    if id.is_empty() {
        return Err(format!("{field} stable ID is required"));
    }
    Ok((id.to_string(), generation))
}
fn positive_generation(value: &str, field: &str) -> Result<i64, String> {
    let generation = value
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("{field} must be a positive integer"))?;
    if generation <= 0 {
        Err(format!("{field} must be a positive integer"))
    } else {
        Ok(generation)
    }
}
fn required(value: &str, field: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(value.to_string())
    }
}

#[component]
fn PlanReview(
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    on_apply: Callback<()>,
) -> impl IntoView {
    view! { {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })} }
}
fn plan<Req: serde::Serialize + 'static>(
    client: ApiClient,
    path: &'static str,
    request: Req,
    idempotency_key: String,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    draft_epoch: Option<RwSignal<u64>>,
) {
    let planned_epoch = draft_epoch.map(|epoch| (epoch, epoch.get_untracked()));
    busy.set(true);
    error.set(None);
    pending.set(None);
    spawn_local(async move {
        let result = client
            .call::<_, aos_proto_types::TopologyPlanResponse>(path, &request)
            .await
            .map_err(|failure| failure.to_string())
            .and_then(|response| PendingPlan::from_response(response, idempotency_key));
        match result {
            Ok(reviewed)
                if planned_epoch
                    .as_ref()
                    .map_or(true, |(epoch, planned)| epoch.get_untracked() == *planned) =>
            {
                pending.set(Some(reviewed));
            }
            Ok(_) => {}
            Err(detail) => error.set(Some(detail)),
        }
        busy.set(false);
    });
}

fn apply_route(
    client: ApiClient,
    path: &'static str,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) -> Callback<()> {
    Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RouteResponse>(path, &reviewed.route_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}
fn registry_surface(path: &str) -> aos_proto_types::SurfaceRef {
    aos_proto_types::SurfaceRef {
        target: Some(aos_proto_types::surface_ref::Target::RegistrySlug(
            path.to_string(),
        )),
    }
}
fn cache_surface(path: &str) -> aos_proto_types::SurfaceRef {
    aos_proto_types::SurfaceRef {
        target: Some(aos_proto_types::surface_ref::Target::CacheSlug(
            path.to_string(),
        )),
    }
}
pub(super) fn reload() {
    crate::app::refresh();
}
