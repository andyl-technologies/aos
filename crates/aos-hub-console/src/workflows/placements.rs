//! Registry and cache placement topology workflows.
//!
//! Desired configuration, controller observations, and derived read/write
//! authority remain visually distinct. Every mutation is scoped by an exact
//! typed surface reference and reviewed against the placement revision.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::resources::UnavailableWorkflow;

/// Renders placement workflows and delegates unrelated pages onward.
#[component]
pub(super) fn PlacementWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Registry { path }, "placements") => view! {
            <Placements client=client surface=registry_surface(path)/>
        }
        .into_any(),
        (
            ConsoleScope::Cache {
                organization,
                cache,
            },
            "placements",
        ) => view! {
            <Placements client=client surface=cache_surface(&format!("{organization}/{cache}"))/>
        }
        .into_any(),
        _ => view! { <UnavailableWorkflow workflow=route.page.workflow/> }.into_any(),
    }
}

#[component]
fn Placements(client: ApiClient, surface: aos_proto_types::SurfaceRef) -> impl IntoView {
    let list_client = client.clone();
    let list_surface = surface.clone();
    let placements = LocalResource::new(move || {
        let client = list_client.clone();
        let surface = list_surface.clone();
        async move {
            client
                .call::<_, aos_proto_types::ListPlacementsResponse>(
                    aos_proto_types::TOPOLOGY_SERVICE_LIST_PLACEMENTS_PATH,
                    &aos_proto_types::ListPlacementsRequest {
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
    let create_surface = surface;

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"Physical topology"</p><h2>"Storage & replicas"</h2><p>"Placements connect this logical surface to storage bindings; desired state and controller evidence are shown separately."</p></div></div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading placements…"</p> }>
                    {move || {
                        let client = view_client.clone();
                        let surface = view_surface.clone();
                        Suspend::new(async move {
                            match placements.await.as_ref() {
                                Ok(response) if response.placements.is_empty() => view! { <p class="muted">"No placements for this surface."</p> }.into_any(),
                                Ok(response) => view! { <div class="binding-list">{response.placements.iter().cloned().map(|placement| view! { <PlacementCard client=client.clone() surface=surface.clone() placement=placement/> }).collect_view()}</div> }.into_any(),
                                Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section>
            <PlacementCreate client=client surface=create_surface/>
        </div>
    }
}

#[component]
fn PlacementCreate(client: ApiClient, surface: aos_proto_types::SurfaceRef) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let binding = RwSignal::new(String::new());
    let prefix = RwSignal::new(String::new());
    let kind = RwSignal::new("complete".to_string());
    let state = RwSignal::new("active".to_string());
    let read_enabled = RwSignal::new(true);
    let read_order = RwSignal::new("0".to_string());
    let range_start = RwSignal::new("0".to_string());
    let range_end = RwSignal::new("65536".to_string());
    let conditional_writes = RwSignal::new(false);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let order = match read_order.get_untracked().parse::<i64>() {
            Ok(value) => value,
            Err(_) => {
                error.set(Some("Read order must be an integer".to_string()));
                return;
            }
        };
        let placement_kind = kind.get_untracked();
        let hash_range = match placement_range(
            &placement_kind,
            &range_start.get_untracked(),
            &range_end.get_untracked(),
        ) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        if placement_kind == "archive" && read_enabled.get_untracked() {
            error.set(Some("Archive placements cannot enable reads".to_string()));
            return;
        }
        let idempotency_key = idempotency_key("placement-create");
        let request = aos_proto_types::PlanCreatePlacementRequest {
            surface: Some(surface.clone()),
            name: name.get_untracked().trim().to_string(),
            storage_binding_id: binding.get_untracked().trim().to_string(),
            prefix: prefix.get_untracked().trim().to_string(),
            kind: placement_kind,
            desired_state: state.get_untracked(),
            desired_read_enabled: Some(read_enabled.get_untracked()),
            read_order: Some(order),
            hash_range,
            requires_conditional_writes: conditional_writes.get_untracked(),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: String::new(),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_CREATE_PLACEMENT_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let on_apply = apply::<aos_proto_types::PlacementResponse>(
        client,
        aos_proto_types::TOPOLOGY_SERVICE_CREATE_PLACEMENT_PATH,
        pending,
        error,
        busy,
    );

    view! {
        <section class="panel editor-panel"><h2>"Create placement"</h2><form class="editor-form" on:submit=on_plan><label><span>"Name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label><label><span>"Storage binding ID"</span><input required prop:value=move || binding.get() on:input=move |event| binding.set(event_target_value(&event))/></label><label><span>"Object prefix"</span><input required prop:value=move || prefix.get() on:input=move |event| prefix.set(event_target_value(&event))/></label><label><span>"Kind"</span><select prop:value=move || kind.get() on:change=move |event| kind.set(event_target_value(&event))><option value="complete">"Complete"</option><option value="shard">"Shard"</option><option value="archive">"Archive"</option></select></label><label><span>"Desired state"</span><select prop:value=move || state.get() on:change=move |event| state.set(event_target_value(&event))><option value="active">"Active"</option><option value="draining">"Draining"</option><option value="offline">"Offline"</option></select></label><label><span>"Read order"</span><input required type="number" prop:value=move || read_order.get() on:input=move |event| read_order.set(event_target_value(&event))/></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || read_enabled.get() on:change=move |event| read_enabled.set(event_target_checked(&event))/><span>"Enable reads"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || conditional_writes.get() on:change=move |event| conditional_writes.set(event_target_checked(&event))/><span>"Require conditional writes"</span></label>{move || (kind.get() == "shard").then(|| view! { <label><span>"Hash range start"</span><input required type="number" min="0" max="65535" prop:value=move || range_start.get() on:input=move |event| range_start.set(event_target_value(&event))/></label><label><span>"Hash range end"</span><input required type="number" min="1" max="65536" prop:value=move || range_end.get() on:input=move |event| range_end.set(event_target_value(&event))/></label> })}<div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review placement"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section>
    }
}

#[component]
fn PlacementCard(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    placement: aos_proto_types::Placement,
) -> impl IntoView {
    let spec = placement.spec.clone().unwrap_or_default();
    let observation = placement.observation.clone().unwrap_or_default();
    let status = placement.status.clone().unwrap_or_default();
    let state = RwSignal::new(spec.desired_state.clone());
    let read_enabled = RwSignal::new(spec.desired_read_enabled);
    let read_order = RwSignal::new(spec.read_order.to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let update_surface = surface.clone();
    let update_placement = placement.clone();
    let on_update = move |event: SubmitEvent| {
        event.prevent_default();
        let order = match read_order.get_untracked().parse::<i64>() {
            Ok(value) => value,
            Err(_) => {
                error.set(Some("Read order must be an integer".to_string()));
                return;
            }
        };
        let idempotency_key = idempotency_key("placement-update");
        let request = aos_proto_types::PlanUpdatePlacementRequest {
            surface: Some(update_surface.clone()),
            name: update_placement.name.clone(),
            expected_resource_version: update_placement.resource_version.clone(),
            desired_state: state.get_untracked(),
            desired_read_enabled: Some(read_enabled.get_untracked()),
            read_order: Some(order),
            update_mask: vec![
                "desired_state".to_string(),
                "desired_read_enabled".to_string(),
                "read_order".to_string(),
            ],
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_UPDATE_PLACEMENT_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let on_apply = apply::<aos_proto_types::PlacementResponse>(
        client.clone(),
        aos_proto_types::TOPOLOGY_SERVICE_UPDATE_PLACEMENT_PATH,
        pending,
        error,
        busy,
    );

    view! {
        <details class="binding-card"><summary><div><span class="resource-kind">{status.derived_role.clone()}</span><h3>{placement.name.clone()}</h3><code>{format!("{}:{}", placement.storage_binding_name, placement.prefix)}</code></div><StatusBadge state=observation.state.clone() positive=observation.state == "ready"/></summary><div class="binding-details"><div class="resource-identity"><div><span>"Kind"</span><strong>{spec.kind}</strong></div><div><span>"Desired state"</span><strong>{spec.desired_state}</strong></div><div><span>"Observed completeness"</span><strong>{observation.completeness}</strong></div><div><span>"Effective read"</span><strong>{yes_no(status.effective_read_enabled)}</strong></div><div><span>"Effective write"</span><strong>{yes_no(status.effective_write_enabled)}</strong></div><div><span>"Version"</span><code>{placement.resource_version.clone()}</code></div></div><div class="subworkflow-grid"><section class="subworkflow"><h4>"Desired placement state"</h4><form class="stacked-form" on:submit=on_update><label><span>"State"</span><select prop:value=move || state.get() on:change=move |event| state.set(event_target_value(&event))><option value="active">"Active"</option><option value="draining">"Draining"</option><option value="offline">"Offline"</option></select></label><label><span>"Read order"</span><input type="number" prop:value=move || read_order.get() on:input=move |event| read_order.set(event_target_value(&event))/></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || read_enabled.get() on:change=move |event| read_enabled.set(event_target_checked(&event))/><span>"Enable reads"</span></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review update"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section><PlacementActions client=client surface=surface placement=placement/></div></div></details>
    }
}

#[component]
fn PlacementActions(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    placement: aos_proto_types::Placement,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let action = RwSignal::new(String::new());
    let plan_client = client.clone();
    let request_surface = surface;
    let request_placement = placement.clone();
    let on_action = Callback::new(move |selected: &'static str| {
        action.set(selected.to_string());
        let idempotency_key = idempotency_key(&format!("placement-{selected}"));
        let request = aos_proto_types::PlacementMutationRequest {
            surface: Some(request_surface.clone()),
            placement_name: request_placement.name.clone(),
            expected_resource_version: Some(request_placement.resource_version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        let path = match selected {
            "promote" => aos_proto_types::TOPOLOGY_SERVICE_PLAN_PROMOTE_PLACEMENT_PATH,
            "drain" => aos_proto_types::TOPOLOGY_SERVICE_PLAN_DRAIN_PLACEMENT_PATH,
            "delete" => aos_proto_types::TOPOLOGY_SERVICE_PLAN_DELETE_PLACEMENT_PATH,
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
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let path = match action.get_untracked().as_str() {
            "promote" => aos_proto_types::TOPOLOGY_SERVICE_PROMOTE_PLACEMENT_PATH,
            "drain" => aos_proto_types::TOPOLOGY_SERVICE_DRAIN_PLACEMENT_PATH,
            "delete" => aos_proto_types::TOPOLOGY_SERVICE_DELETE_PLACEMENT_PATH,
            _ => return,
        };
        let client = apply_client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, serde_json::Value>(path, &reviewed.topology_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    let promote_action = on_action.clone();
    let promote = move |_| promote_action.run("promote");
    let drain_action = on_action.clone();
    let drain = move |_| drain_action.run("drain");
    let delete = move |_| on_action.run("delete");

    view! {
        <section class="subworkflow"><h4>"Lifecycle"</h4><p>"Promotion changes single-writer authority; draining and deletion remain blocked until safety predicates pass."</p><div class="form-actions"><button class="secondary-button" type="button" disabled=move || busy.get() on:click=promote>"Review promotion"</button><button class="secondary-button" type="button" disabled=move || busy.get() on:click=drain>"Review drain"</button><button class="danger-button" type="button" disabled=move || busy.get() on:click=delete>"Review deletion"</button></div><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section>
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

fn apply<Resp: serde::de::DeserializeOwned + 'static>(
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
                .call::<_, Resp>(path, &reviewed.topology_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}

fn placement_range(
    kind: &str,
    start: &str,
    end: &str,
) -> Result<Option<aos_proto_types::HashRangeV1>, String> {
    if kind != "shard" {
        return Ok(None);
    }
    let start = start
        .parse::<u32>()
        .map_err(|_| "Hash range start must be an integer".to_string())?;
    let end = end
        .parse::<u32>()
        .map_err(|_| "Hash range end must be an integer".to_string())?;
    if start >= end || end > 65_536 {
        return Err("Hash range must satisfy 0 <= start < end <= 65536".to_string());
    }
    Ok(Some(aos_proto_types::HashRangeV1 { start, end }))
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
fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
fn reload() {
    if let Some(window) = leptos::web_sys::window() {
        let _ = window.location().reload();
    }
}
