//! Registry and cache delivery-route workflows.
//!
//! Routes pin exact endpoint, policy, and gateway generations. Hub proxy and
//! redirect routes own an access policy; direct routes inherit access and path
//! from their exact storage-gateway generation.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::access_policy::{
    access_policy_name, canonical_path, AccessPolicyFields, AccessPolicySignals,
};
use super::cache_integrations::CacheIntegrationWorkflow;

/// Renders route workflows and delegates unrelated pages onward.
#[component]
pub(super) fn DeliveryRouteWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Registry { path }, "delivery") => view! {
            <DeliveryRoutes client=client surface=registry_surface(path)/>
        }
        .into_any(),
        (
            ConsoleScope::Cache {
                organization,
                cache,
            },
            "delivery",
        ) => view! {
            <DeliveryRoutes client=client surface=cache_surface(&format!("{organization}/{cache}"))/>
        }
        .into_any(),
        _ => view! { <CacheIntegrationWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn DeliveryRoutes(client: ApiClient, surface: aos_proto_types::SurfaceRef) -> impl IntoView {
    let read_client = client.clone();
    let read_surface = surface.clone();
    let routes = LocalResource::new(move || {
        let client = read_client.clone();
        let surface = read_surface.clone();
        async move {
            client
                .call::<_, aos_proto_types::ListRoutesResponse>(
                    aos_proto_types::ROUTE_SERVICE_LIST_ROUTES_PATH,
                    &aos_proto_types::ListRoutesRequest {
                        surface: Some(surface),
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await
        }
    });
    let view_client = client.clone();
    let view_surface = surface.clone();
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
    let canonical_client = client.clone();
    let canonical_surface = surface.clone();
    let create_client = client;
    let create_surface = surface;

    view! {
        <div class="workflow-stack"><section class="panel resource-panel"><div class="section-heading"><div><p class="section-kicker">"Simultaneous delivery paths"</p><h2>"Delivery routes"</h2><p>"Multiple Hub-proxied, redirected, CDN-fronted, and direct routes can serve the same logical surface concurrently."</p></div></div><Suspense fallback=move || view! { <p class="loading-row">"Loading delivery routes…"</p> }>{move || { let client = view_client.clone(); let surface = view_surface.clone(); Suspend::new(async move { match routes.await.as_ref() { Ok(response) if response.routes.is_empty() => view! { <p class="muted">"No delivery routes for this surface."</p> }.into_any(), Ok(response) => view! { <div class="binding-list">{response.routes.iter().cloned().map(|route| view! { <RouteCard client=client.clone() surface=surface.clone() route=route/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section><Suspense fallback=move || view! { <section class="panel"><p class="loading-row">"Loading canonical routes…"</p></section> }>{move || { let client = canonical_client.clone(); let surface = canonical_surface.clone(); Suspend::new(async move { match topology.await.as_ref() { Ok(response) => view! { <CanonicalRoutes client=client surface=surface canonical=response.canonical_routes.clone() routes=response.routes.clone()/> }.into_any(), Err(failure) => view! { <section class="panel"><InlineError detail=failure.to_string()/></section> }.into_any() } }) }}</Suspense><RouteCreate client=create_client surface=create_surface/></div>
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
    enabled: RwSignal<bool>,
    access: AccessPolicySignals,
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
            enabled: RwSignal::new(false),
            access: AccessPolicySignals::public(),
        }
    }

    fn from_spec(spec: &aos_proto_types::DeliveryRouteSpec) -> Self {
        use aos_proto_types::delivery_route_target::Target;
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
}

#[component]
fn RouteFields(signals: RouteSignals, immutable_identity: bool) -> impl IntoView {
    view! {
        {(!immutable_identity).then(|| view! { <label><span>"Endpoint stable ID"</span><input required prop:value=move || signals.endpoint_id.get() on:input=move |event| signals.endpoint_id.set(event_target_value(&event))/></label><label><span>"Base path"</span><input required prop:value=move || signals.base_path.get() on:input=move |event| signals.base_path.set(event_target_value(&event))/></label> })}
        <label><span>"Endpoint generation"</span><input required type="number" min="1" prop:value=move || signals.endpoint_generation.get() on:input=move |event| signals.endpoint_generation.set(event_target_value(&event))/></label>
        <label><span>"Delivery mode"</span><select prop:value=move || signals.mode.get() on:change=move |event| signals.mode.set(event_target_value(&event))><option value="hub-proxy">"Hub proxy"</option><option value="hub-redirect">"Hub redirect"</option><option value="direct">"Direct gateway"</option></select></label>
        {move || if signals.mode.get() == "direct" { view! { <label><span>"Placement"</span><input required prop:value=move || signals.target_ref.get() on:input=move |event| signals.target_ref.set(event_target_value(&event))/></label><label><span>"Gateway generation (stable-id@revision)"</span><input required prop:value=move || signals.gateway_ref.get() on:input=move |event| signals.gateway_ref.set(event_target_value(&event))/></label> }.into_any() } else { view! { <label><span>"Target kind"</span><select prop:value=move || signals.target_kind.get() on:change=move |event| signals.target_kind.set(event_target_value(&event))><option value="placement">"Placement"</option><option value="policy">"Placement policy revision"</option></select></label><label><span>"Target reference"</span><input required prop:value=move || signals.target_ref.get() on:input=move |event| signals.target_ref.set(event_target_value(&event))/></label><AccessPolicyFields signals=signals.access allow_hub_auth=true/> }.into_any() }}
        <label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_git.get() on:change=move |event| signals.serves_git.set(event_target_checked(&event))/><span>"Serve Git"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_cache.get() on:change=move |event| signals.serves_cache.set(event_target_checked(&event))/><span>"Serve Nix cache"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.serves_web.get() on:change=move |event| signals.serves_web.set(event_target_checked(&event))/><span>"Serve Web"</span></label>
    }
}

#[component]
fn RouteCreate(client: ApiClient, surface: aos_proto_types::SurfaceRef) -> impl IntoView {
    let stable_id = RwSignal::new(String::new());
    let signals = RouteSignals::empty();
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
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
        );
    };
    let on_apply = apply_route(
        client,
        aos_proto_types::ROUTE_SERVICE_CREATE_ROUTE_PATH,
        pending,
        error,
        busy,
    );
    view! { <section class="panel editor-panel"><h2>"Create delivery route"</h2><form class="editor-form" on:submit=on_plan><label><span>"Stable route ID"</span><input prop:value=move || stable_id.get() on:input=move |event| stable_id.set(event_target_value(&event))/></label><RouteFields signals=signals immutable_identity=false/><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review route"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

#[component]
fn RouteCard(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    route: aos_proto_types::DeliveryRoute,
) -> impl IntoView {
    let spec = route.spec.clone().unwrap_or_default();
    let observation = route.observation.clone().unwrap_or_default();
    let mode = route_mode(&spec);
    view! { <details class="binding-card"><summary><div><span class="resource-kind">{mode}</span><h3>{route.canonical_rendered_url.clone()}</h3><code>{route.stable_id.clone()}</code></div><StatusBadge state=observation.state.clone() positive=observation.state == "healthy"/></summary><div class="binding-details"><div class="resource-identity"><div><span>"Endpoint"</span><code>{format!("{}@{}", spec.endpoint_id, spec.endpoint_generation)}</code></div><div><span>"Target"</span><code>{target_name(&spec)}</code></div><div><span>"Access"</span><strong>{access_policy_name(spec.access_policy.as_ref())}</strong></div><div><span>"Configuration generation"</span><strong>{route.configuration_generation}</strong></div><div><span>"Observed generation"</span><strong>{observation.configuration_generation}</strong></div><div><span>"Version"</span><code>{route.resource_version.clone()}</code></div></div>{(!observation.error.is_empty()).then(|| view! { <InlineError detail=observation.error/> })}<div class="subworkflow-grid"><RouteUpdate client=client.clone() surface=surface.clone() route=route.clone()/><RouteLifecycle client=client.clone() route=route.clone()/></div><RouteExplain client=client.clone() route=route.clone()/><RouteReplace client=client surface=surface route=route/></div></details> }
}

#[component]
fn RouteUpdate(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    route: aos_proto_types::DeliveryRoute,
) -> impl IntoView {
    let signals = RouteSignals::from_spec(&route.spec.clone().unwrap_or_default());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
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
        );
    };
    let on_apply = apply_route(
        client,
        aos_proto_types::ROUTE_SERVICE_UPDATE_ROUTE_PATH,
        pending,
        error,
        busy,
    );
    view! { <section class="subworkflow"><h4>"Update route generation"</h4><form class="stacked-form" on:submit=on_plan><RouteFields signals=signals immutable_identity=true/><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review update"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

#[component]
fn RouteLifecycle(client: ApiClient, route: aos_proto_types::DeliveryRoute) -> impl IntoView {
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
fn RouteExplain(client: ApiClient, route: aos_proto_types::DeliveryRoute) -> impl IntoView {
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
    route: aos_proto_types::DeliveryRoute,
) -> impl IntoView {
    let successor_id = RwSignal::new(String::new());
    let signals = RouteSignals::from_spec(&route.spec.clone().unwrap_or_default());
    signals.enabled.set(false);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
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
        );
    };
    let on_apply = apply_route(
        client,
        aos_proto_types::ROUTE_SERVICE_REPLACE_ROUTE_PATH,
        pending,
        error,
        busy,
    );
    view! { <section class="subworkflow danger-subworkflow"><h4>"Replace route identity"</h4><p>"Endpoint or URL-path identity changes create a distinct disabled successor; they never mutate the live route in place."</p><form class="editor-form" on:submit=on_plan><label><span>"Successor stable ID"</span><input prop:value=move || successor_id.get() on:input=move |event| successor_id.set(event_target_value(&event))/></label><RouteFields signals=signals immutable_identity=false/><button class="danger-button" type="submit" disabled=move || busy.get()>"Review replacement"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

#[component]
fn CanonicalRoutes(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    canonical: Vec<aos_proto_types::CanonicalRoute>,
    routes: Vec<aos_proto_types::DeliveryRoute>,
) -> impl IntoView {
    let audience = RwSignal::new("web".to_string());
    let initial_route = routes
        .iter()
        .find(|value| value.spec.as_ref().is_some_and(|spec| spec.enabled))
        .map(|value| value.stable_id.clone())
        .unwrap_or_default();
    let route_id = RwSignal::new(initial_route);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let request_canonical = canonical.clone();
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
        let request = aos_proto_types::PlanCanonicalRouteRequest {
            surface: Some(surface.clone()),
            audience: selected_audience,
            route_id: route_id.get_untracked(),
            expected_resource_version,
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::ROUTE_SERVICE_PLAN_SET_CANONICAL_ROUTE_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
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
                .call::<_, aos_proto_types::CanonicalRouteResponse>(
                    aos_proto_types::ROUTE_SERVICE_SET_CANONICAL_ROUTE_PATH,
                    &reviewed.canonical_route_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    view! { <section class="panel editor-panel"><div class="section-heading"><div><p class="section-kicker">"Audience defaults"</p><h2>"Canonical routes"</h2><p>"Each audience resolves to one enabled route while alternate routes remain simultaneously available."</p></div></div><div class="compact-list">{canonical.into_iter().map(|value| view! { <div class="compact-list-row"><div><strong>{value.audience}</strong><code>{value.route_id}</code></div></div> }).collect_view()}</div><form class="editor-form" on:submit=on_plan><label><span>"Audience"</span><select prop:value=move || audience.get() on:change=move |event| audience.set(event_target_value(&event))><option value="git">"Git"</option><option value="nix_cache">"Nix cache"</option><option value="web">"Web"</option></select></label><label><span>"Enabled route"</span><select prop:value=move || route_id.get() on:change=move |event| route_id.set(event_target_value(&event))>{routes.iter().filter(|route| route.spec.as_ref().is_some_and(|spec| spec.enabled)).map(|route| view! { <option value=route.stable_id.clone()>{route.canonical_rendered_url.clone()}</option> }).collect_view()}</select></label><div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review canonical selection"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

fn build_spec(
    surface: aos_proto_types::SurfaceRef,
    signals: RouteSignals,
) -> Result<aos_proto_types::DeliveryRouteSpec, String> {
    use aos_proto_types::delivery_route_target::Target;
    let endpoint_generation = positive_generation(
        &signals.endpoint_generation.get_untracked(),
        "Endpoint generation",
    )?;
    let endpoint_id = required(&signals.endpoint_id.get_untracked(), "Endpoint stable ID")?;
    let capabilities = aos_proto_types::RouteCapabilities {
        serves_git: signals.serves_git.get_untracked(),
        serves_cache: signals.serves_cache.get_untracked(),
        serves_web: signals.serves_web.get_untracked(),
    };
    if !capabilities.serves_git && !capabilities.serves_cache && !capabilities.serves_web {
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
    Ok(aos_proto_types::DeliveryRouteSpec {
        surface: Some(surface),
        endpoint_id,
        endpoint_generation,
        base_path,
        target: Some(aos_proto_types::DeliveryRouteTarget {
            target: Some(target),
        }),
        access_policy,
        capabilities: Some(capabilities),
        enabled: signals.enabled.get_untracked(),
    })
}

fn route_mode(spec: &aos_proto_types::DeliveryRouteSpec) -> &'static str {
    use aos_proto_types::delivery_route_target::Target;
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
fn target_name(spec: &aos_proto_types::DeliveryRouteSpec) -> String {
    use aos_proto_types::delivery_route_target::Target;
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
) {
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
                .call::<_, aos_proto_types::DeliveryRouteResponse>(path, &reviewed.route_apply())
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
fn reload() {
    if let Some(window) = leptos::web_sys::window() {
        let _ = window.location().reload();
    }
}
