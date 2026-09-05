//! Registry and cache placement topology workflows.
//!
//! Desired configuration, controller observations, and derived read/write
//! authority remain visually distinct. Every mutation is scoped by an exact
//! typed surface reference and reviewed against the placement revision.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{HashValue, HelpTooltip, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, watch_draft, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::gateways::binding_option_label;
use super::organization_scope::surface_authorization_scope;
use super::placement_policies::{PlacementEquivalencePanel, PlacementPolicyPanel};
use super::routes::RouteWorkflow;

/// Renders placement workflows and delegates unrelated pages onward.
#[component]
pub(super) fn PlacementWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Registry { path }, "placements") => view! {
            <Placements client=client surface=registry_surface(path)/>
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "placements") => view! {
            <Placements client=client surface=cache_surface(path)/>
        }
        .into_any(),
        _ => view! { <RouteWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn Placements(client: ApiClient, surface: aos_proto_types::SurfaceRef) -> impl IntoView {
    let can_manage = client.allows("placement.manage");
    let can_evict = client.allows("cache.gc.execute");
    let can_explain = client.allows("route.read");
    let list_client = client.clone();
    let list_surface = surface.clone();
    let placements = LocalResource::new(move || {
        let client = list_client.clone();
        let surface = list_surface.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListPlacementsResponse, _, _, _>(
                    aos_proto_types::TOPOLOGY_SERVICE_LIST_PLACEMENTS_PATH,
                    move |page_token| aos_proto_types::ListPlacementsRequest {
                        surface: Some(surface.clone()),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.placements, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let view_surface = surface.clone();
    let authority_surface = surface.clone();
    let action = RwSignal::new("overview".to_string());
    let action_client = client.clone();
    let action_surface = surface.clone();

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"Effective storage"</p><div class="section-title"><h2>"Storage & replicas"</h2><HelpTooltip term="Placements" summary="Each placement connects this surface to a storage binding. Effective reads and writes depend on current controller evidence."/></div><p>"See where clients read and writes land. Expand a location to inspect its configuration, move write authority, or review retirement."</p></div></div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading storage locations…"</p> }>
                    {move || {
                        let client = view_client.clone();
                        let surface = view_surface.clone();
                        Suspend::new(async move {
                            match placements.await.as_ref() {
                                Ok(placements) if placements.is_empty() => view! { <p class="muted">"No storage is connected. Add a storage location to begin setup."</p> }.into_any(),
                                Ok(placements) => view! { <div class="binding-list">{placements.iter().cloned().map(|placement| view! { <PlacementCard client=client.clone() surface=surface.clone() placement=placement can_manage=can_manage can_evict=can_evict/> }).collect_view()}</div> }.into_any(),
                                Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section>
            <WriteAuthorityPanel client=client surface=authority_surface/>
            <section class="panel resource-panel">
                <h2>"Storage actions"</h2>
                <div class="editor-form"><label><span>"Choose a task"</span><select prop:value=move || action.get() on:change=move |event| action.set(event_target_value(&event))>
                    <option value="overview">"Choose a task…"</option>
                    {can_manage.then(|| view! { <option value="add">"Add a storage location"</option><option value="replicate">"Copy data to a replica"</option> })}
                    <option value="advanced">"Advanced policies and diagnostics"</option>
                </select></label></div>
                <p class="muted">"To add a replica, first connect its storage location, then copy data from a healthy source. Copying data does not change write authority."</p>
            </section>
            {move || {
                let client = action_client.clone();
                let surface = action_surface.clone();
                match action.get().as_str() {
                    "add" if can_manage => view! { <PlacementSetup client=client surface=surface/> }.into_any(),
                    "replicate" if can_manage => view! {
                        <Suspense fallback=move || view! { <p class="loading-row">"Loading replica choices…"</p> }>
                            {move || { let client = client.clone(); let surface = surface.clone(); Suspend::new(async move {
                                match placements.await.as_ref() {
                                    Ok(items) => view! { <PlacementReplication client=client surface=surface placements=items.clone()/> }.into_any(),
                                    Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                                }
                            }) }}
                        </Suspense>
                    }.into_any(),
                    "advanced" => view! {
                        <PlacementPolicyPanel client=client.clone() surface=surface.clone()/>
                        <PlacementEquivalencePanel client=client.clone() surface=surface.clone()/>
                        <SurfaceDiagnostics client=client surface=surface can_explain=can_explain/>
                    }.into_any(),
                    _ => ().into_any(),
                }
            }}
        </div>
    }
}

#[component]
fn PlacementSetup(client: ApiClient, surface: aos_proto_types::SurfaceRef) -> impl IntoView {
    let binding_client = client.clone();
    let binding_surface = surface.clone();
    let bindings = LocalResource::new(move || {
        let client = binding_client.clone();
        let surface = binding_surface.clone();
        async move { load_surface_bindings(&client, &surface).await }
    });
    view! {
                <Suspense fallback=move || view! { <section class="panel editor-panel"><p class="loading-row">"Loading bindings…"</p></section> }>
                    {move || {
                        let client = client.clone();
                        let surface = surface.clone();
                        Suspend::new(async move {
                            match bindings.await.as_ref() {
                                Ok(bindings) => view! { <PlacementCreate client=client surface=surface bindings=bindings.clone()/> }.into_any(),
                                Err(detail) => view! { <section class="panel editor-panel"><InlineError detail=detail.clone()/></section> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
    }
}

async fn load_surface_bindings(
    client: &ApiClient,
    surface: &aos_proto_types::SurfaceRef,
) -> Result<Vec<aos_proto_types::Binding>, String> {
    let (owner_scope_key, _) = surface_authorization_scope(client, surface).await?;
    client
        .collect_pages::<_, aos_proto_types::ListBindingsResponse, _, _, _>(
            aos_proto_types::BINDING_SERVICE_LIST_BINDINGS_PATH,
            move |page_token| aos_proto_types::ListBindingsRequest {
                owner_scope_key: owner_scope_key.clone(),
                page_size: 100,
                page_token,
                include_granted: true,
            },
            |response| (response.bindings, response.next_page_token),
        )
        .await
        .map_err(|failure| failure.to_string())
}

#[component]
fn PlacementCreate(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    bindings: Vec<aos_proto_types::Binding>,
) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let binding = RwSignal::new(
        bindings
            .first()
            .map(|binding| binding.stable_id.clone())
            .unwrap_or_default(),
    );
    // Canonical slugs are globally unique and are the public object path for
    // default delivery. Keep opaque stable IDs inside the control plane rather
    // than asking operators to copy them into client-facing storage paths.
    let canonical_prefix = match surface.target.as_ref() {
        Some(aos_proto_types::surface_ref::Target::RegistrySlug(slug))
        | Some(aos_proto_types::surface_ref::Target::CacheSlug(slug)) => slug.clone(),
        None => String::new(),
    };
    let prefix = RwSignal::new(canonical_prefix);
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
    let draft_epoch = watch_draft(
        move || {
            let _ = (
                name.get(),
                binding.get(),
                prefix.get(),
                kind.get(),
                state.get(),
                read_enabled.get(),
                read_order.get(),
                range_start.get(),
                range_end.get(),
                conditional_writes.get(),
            );
        },
        pending,
        error,
    );
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
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
            binding_id: binding.get_untracked().trim().to_string(),
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
            Some(draft_epoch),
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
        <section class="panel editor-panel"><h2>"Add a storage location"</h2><p>"Connect existing storage to this surface. New locations become usable only when their controller evidence is ready."</p><form class="editor-form" on:submit=on_plan><label><span>"Name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label><label><span>"Binding"</span><select required prop:value=move || binding.get() on:change=move |event| binding.set(event_target_value(&event))>{bindings.iter().map(|choice| view! { <option value=choice.stable_id.clone()>{binding_option_label(choice)}</option> }).collect_view()}</select>{bindings.is_empty().then(|| view! { <small>"No compatible bindings are owned by or explicitly granted to this surface's owner scope."</small> })}</label><label><span>"Object prefix"</span><input required prop:value=move || prefix.get() on:input=move |event| prefix.set(event_target_value(&event))/><small>"Routes map this binding-relative prefix to an explicitly configured delivery URL."</small></label><label><span>"Kind"</span><select prop:value=move || kind.get() on:change=move |event| kind.set(event_target_value(&event))><option value="complete">"Complete"</option><option value="shard">"Shard"</option><option value="archive">"Archive"</option></select></label><label><span>"Desired state"</span><select prop:value=move || state.get() on:change=move |event| state.set(event_target_value(&event))><option value="active">"Active"</option><option value="draining">"Draining"</option><option value="offline">"Offline"</option></select></label><label><span>"Read order"</span><input required type="number" prop:value=move || read_order.get() on:input=move |event| read_order.set(event_target_value(&event))/></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || read_enabled.get() on:change=move |event| read_enabled.set(event_target_checked(&event))/><span>"Enable reads"</span></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || conditional_writes.get() on:change=move |event| conditional_writes.set(event_target_checked(&event))/><span>"Require conditional writes"</span></label>{move || (kind.get() == "shard").then(|| view! { <label><span>"Hash range start"</span><input required type="number" min="0" max="65535" prop:value=move || range_start.get() on:input=move |event| range_start.set(event_target_value(&event))/></label><label><span>"Hash range end"</span><input required type="number" min="1" max="65536" prop:value=move || range_end.get() on:input=move |event| range_end.set(event_target_value(&event))/></label> })}<div class="form-actions"><button class="button" type="submit" disabled=move || busy.get() || binding.get().is_empty()>"Review placement"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section>
    }
}

#[component]
fn PlacementCard(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    placement: aos_proto_types::Placement,
    can_manage: bool,
    can_evict: bool,
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
    let draft_epoch = watch_draft(
        move || {
            let _ = (state.get(), read_enabled.get(), read_order.get());
        },
        pending,
        error,
    );
    let plan_client = client.clone();
    let update_surface = surface.clone();
    let update_placement = placement.clone();
    let on_update = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
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
            Some(draft_epoch),
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
        <details class="binding-card"><summary><div><span class="resource-kind">{status.derived_role.clone()}</span><h3>{placement.name.clone()}</h3><code>{format!("{}:{}", placement.binding_name, placement.prefix)}</code><p>{format!("Reads: {} · Writes: {}", yes_no(status.effective_read_enabled), yes_no(status.effective_write_enabled))}</p></div><StatusBadge state=observation.state.clone() positive=observation.state == "ready"/></summary><div class="binding-details"><div class="resource-identity"><div><span>"Kind"</span><strong>{spec.kind}</strong></div><div><span>"Desired state"</span><strong>{spec.desired_state}</strong></div><div><span>"Observed completeness"</span><strong>{observation.completeness}</strong></div><div><span>"Effective read"</span><strong>{yes_no(status.effective_read_enabled)}</strong></div><div><span>"Effective write"</span><strong>{yes_no(status.effective_write_enabled)}</strong></div><div><span>"Version"</span><code>{placement.resource_version.clone()}</code></div></div><div class="subworkflow-grid">{can_manage.then(|| view! { <section class="subworkflow"><h4>"Desired placement state"</h4><form class="stacked-form" on:submit=on_update><label><span>"State"</span><select prop:value=move || state.get() on:change=move |event| state.set(event_target_value(&event))><option value="active">"Active"</option><option value="draining">"Draining"</option><option value="offline">"Offline"</option></select></label><label><span>"Read order"</span><input type="number" prop:value=move || read_order.get() on:input=move |event| read_order.set(event_target_value(&event))/></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || read_enabled.get() on:change=move |event| read_enabled.set(event_target_checked(&event))/><span>"Enable reads"</span></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review update"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> })}{(can_manage || can_evict).then(|| view! { <PlacementActions client=client.clone() surface=surface.clone() placement=placement.clone() can_manage=can_manage can_evict=can_evict/> })}</div>{can_manage.then(|| view! { <PlacementOperations client=client surface=surface placement=placement/> })}</div></details>
    }
}

#[component]
fn PlacementActions(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    placement: aos_proto_types::Placement,
    can_manage: bool,
    can_evict: bool,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let action = RwSignal::new(String::new());
    let plan_client = client.clone();
    let eviction_client = client.clone();
    let request_surface = surface.clone();
    let eviction_surface = surface.clone();
    let request_placement = placement.clone();
    let eviction_placement = placement.clone();
    let cache_surface = can_evict
        && matches!(
            surface.target,
            Some(aos_proto_types::surface_ref::Target::CacheSlug(_))
        );
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
            "cancel-drain" => aos_proto_types::TOPOLOGY_SERVICE_PLAN_CANCEL_PLACEMENT_DRAIN_PATH,
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
            None,
        );
    });
    let eviction_pending = RwSignal::new(None::<PendingPlan>);
    let eviction_error = RwSignal::new(None::<String>);
    let eviction_busy = RwSignal::new(false);
    let on_eviction = move |_| {
        let idempotency_key = idempotency_key("placement-eviction");
        let request = aos_proto_types::PlanRunPlacementEvictionRequest {
            surface: Some(eviction_surface.clone()),
            placement_name: eviction_placement.name.clone(),
            expected_resource_version: Some(eviction_placement.resource_version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            eviction_client.clone(),
            aos_proto_types::BINARY_CACHE_SERVICE_PLAN_RUN_PLACEMENT_EVICTION_PATH,
            request,
            idempotency_key,
            eviction_pending,
            eviction_error,
            eviction_busy,
            None,
        );
    };
    let on_apply_eviction = apply::<aos_proto_types::OperationResponse>(
        client.clone(),
        aos_proto_types::BINARY_CACHE_SERVICE_RUN_PLACEMENT_EVICTION_PATH,
        eviction_pending,
        eviction_error,
        eviction_busy,
    );
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let path = match action.get_untracked().as_str() {
            "promote" => aos_proto_types::TOPOLOGY_SERVICE_PROMOTE_PLACEMENT_PATH,
            "drain" => aos_proto_types::TOPOLOGY_SERVICE_DRAIN_PLACEMENT_PATH,
            "cancel-drain" => aos_proto_types::TOPOLOGY_SERVICE_CANCEL_PLACEMENT_DRAIN_PATH,
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
    let cancel_drain_action = on_action.clone();
    let cancel_drain = move |_| cancel_drain_action.run("cancel-drain");
    let delete = move |_| on_action.run("delete");
    let draining = placement
        .spec
        .as_ref()
        .is_some_and(|spec| spec.desired_state == "draining");
    view! {
        <section class="subworkflow"><h4>"Move writes or retire this location"</h4><p>"To retire storage, review a drain, wait for its blockers to clear, then review deletion. Promotion moves write authority to this location after verification."</p><div class="form-actions">{can_manage.then(|| view! { <button class="secondary-button" type="button" disabled=move || busy.get() on:click=promote>"Review promotion"</button>{if draining { view! { <button class="secondary-button" type="button" disabled=move || busy.get() on:click=cancel_drain>"Review cancel drain"</button> }.into_any() } else { view! { <button class="secondary-button" type="button" disabled=move || busy.get() on:click=drain>"Review drain"</button> }.into_any() }}<button class="danger-button" type="button" disabled=move || busy.get() on:click=delete>"Review deletion"</button> })}{cache_surface.then(|| view! { <button class="danger-button" type="button" disabled=move || eviction_busy.get() on:click=on_eviction>"Review physical eviction"</button> })}</div>{can_manage.then(|| view! { <PlanReview pending=pending error=error busy=busy on_apply=on_apply/> })}<PlanReview pending=eviction_pending error=eviction_error busy=eviction_busy on_apply=on_apply_eviction/></section>
    }
}

#[component]
fn SurfaceDiagnostics(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    can_explain: bool,
) -> impl IntoView {
    let url = RwSignal::new(String::new());
    let machine_path = RwSignal::new(String::new());
    let access_class = RwSignal::new("web".to_string());
    let explanation = RwSignal::new(None::<aos_proto_types::ExplainSurfaceRequestResponse>);
    let explain_error = RwSignal::new(None::<String>);
    let explain_busy = RwSignal::new(false);
    let explain_client = client.clone();
    let explain_surface = surface.clone();
    let on_explain = move |event: SubmitEvent| {
        event.prevent_default();
        let client = explain_client.clone();
        let request = aos_proto_types::ExplainSurfaceRequestRequest {
            surface: Some(explain_surface.clone()),
            url: url.get_untracked().trim().to_string(),
            machine_path: machine_path.get_untracked().trim().to_string(),
            access_class: access_class.get_untracked(),
        };
        explain_error.set(None);
        explanation.set(None);
        explain_busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ExplainSurfaceRequestResponse>(
                    aos_proto_types::TOPOLOGY_SERVICE_EXPLAIN_SURFACE_REQUEST_PATH,
                    &request,
                )
                .await
            {
                Ok(response) => explanation.set(Some(response)),
                Err(failure) => explain_error.set(Some(failure.to_string())),
            }
            explain_busy.set(false);
        });
    };

    let object_ref = RwSignal::new(String::new());
    let presences = RwSignal::new(None::<Vec<aos_proto_types::ObjectPresence>>);
    let presence_error = RwSignal::new(None::<String>);
    let presence_busy = RwSignal::new(false);
    let presence_client = client;
    let presence_surface = surface;
    let on_presence = move |event: SubmitEvent| {
        event.prevent_default();
        let object = object_ref.get_untracked().trim().to_string();
        if object.is_empty() {
            presence_error.set(Some("Object reference is required".to_string()));
            return;
        }
        let client = presence_client.clone();
        let surface = presence_surface.clone();
        presence_error.set(None);
        presences.set(None);
        presence_busy.set(true);
        spawn_local(async move {
            match client
                .collect_pages::<_, aos_proto_types::ListObjectPresenceResponse, _, _, _>(
                    aos_proto_types::TOPOLOGY_SERVICE_LIST_OBJECT_PRESENCE_PATH,
                    move |page_token| aos_proto_types::ListObjectPresenceRequest {
                        surface: Some(surface.clone()),
                        object_ref: object.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.presences, response.next_page_token),
                )
                .await
            {
                Ok(response) => presences.set(Some(response)),
                Err(failure) => presence_error.set(Some(failure.to_string())),
            }
            presence_busy.set(false);
        });
    };

    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Request topology"</p><h2>"Explain routing & object presence"<HelpTooltip term="Explain routing & object presence" summary="Resolve one public request through the live route set, or inspect one object's evidence across every placement."/></h2></div></div>
            <div class="subworkflow-grid">
                {can_explain.then(|| view! { <section class="subworkflow">
                    <h4>"Explain a request"</h4>
                    <form class="stacked-form" on:submit=on_explain>
                        <label><span>"Absolute URL"</span><input required type="url" placeholder="https://cache.example/nar/object.nar.zst" prop:value=move || url.get() on:input=move |event| url.set(event_target_value(&event))/></label>
                        <label><span>"Machine path override (optional)"</span><input placeholder="/nar/object.nar.zst" prop:value=move || machine_path.get() on:input=move |event| machine_path.set(event_target_value(&event))/></label>
                        <label><span>"Access class"</span><select prop:value=move || access_class.get() on:change=move |event| access_class.set(event_target_value(&event))><option value="web">"Web"</option><option value="git">"Git"</option><option value="nix_cache">"Nix cache"</option></select></label>
                        <button class="secondary-button" type="submit" disabled=move || explain_busy.get()>"Explain request"</button>
                    </form>
                    {move || explain_error.get().map(|detail| view! { <InlineError detail=detail/> })}
                    {move || explanation.get().map(|result| view! { <article class="revision-card"><div class="resource-identity"><div><span>"Normalized URL"</span><code>{result.normalized_url}</code></div><div><span>"Selected route"</span><code>{display_or(&result.selected_route_id, "none")}</code></div></div><h5>"Decisions"</h5><div class="compact-list">{result.decisions.into_iter().map(|decision| view! { <p>{decision}</p> }).collect_view()}</div>{(!result.rejection_reasons.is_empty()).then(|| view! { <h5>"Rejections"</h5><div class="compact-list">{result.rejection_reasons.into_iter().map(|reason| view! { <p>{reason}</p> }).collect_view()}</div> })}</article> })}
                </section> })}
                <section class="subworkflow">
                    <h4>"Locate an object"</h4>
                    <form class="stacked-form" on:submit=on_presence><label><span>"Object reference"</span><input required placeholder="store hash, path, or release object" prop:value=move || object_ref.get() on:input=move |event| object_ref.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || presence_busy.get()>"Inspect placement evidence"</button></form>
                    {move || presence_error.get().map(|detail| view! { <InlineError detail=detail/> })}
                    {move || presences.get().map(|items| if items.is_empty() { view! { <p class="muted">"No placement has reported this object."</p> }.into_any() } else { view! { <div class="compact-list">{items.into_iter().map(|item| view! { <div class="compact-list-row"><div><strong>{item.placement_name}</strong>{if item.content_digest.is_empty() { view! { <span>"digest unavailable"</span> }.into_any() } else { view! { <HashValue value=item.content_digest/> }.into_any() }}</div><span>{format!("{} bytes", item.size)}</span><StatusBadge state=item.state.clone() positive=item.state == "present"/></div> }).collect_view()}</div> }.into_any() })}
                </section>
            </div>
        </section>
    }
}

#[component]
fn WriteAuthorityPanel(client: ApiClient, surface: aos_proto_types::SurfaceRef) -> impl IntoView {
    let read_client = client.clone();
    let read_surface = surface.clone();
    let authority = LocalResource::new(move || {
        let client = read_client.clone();
        let surface = read_surface.clone();
        async move {
            client
                .call::<_, aos_proto_types::GetWriteAuthorityResponse>(
                    aos_proto_types::TOPOLOGY_SERVICE_GET_WRITE_AUTHORITY_PATH,
                    &aos_proto_types::GetWriteAuthorityRequest {
                        surface: Some(surface),
                    },
                )
                .await
        }
    });

    view! {
        <section class="panel resource-panel"><div class="section-heading"><div><p class="section-kicker">"Single writer"</p><h2>"Write authority"<HelpTooltip term="Write authority" summary="Desired and controller-observed writer generations must reconcile before writes become effective."/></h2></div></div><Suspense fallback=move || view! { <p class="loading-row">"Loading write authority…"</p> }>{move || { let client = client.clone(); let surface = surface.clone(); Suspend::new(async move { match authority.await.as_ref() { Ok(response) => view! { <WriteAuthorityState client=client surface=surface authority=response.authority.clone()/> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section>
    }
}

#[component]
fn WriteAuthorityState(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    authority: Option<aos_proto_types::SurfaceWriteAuthority>,
) -> impl IntoView {
    let can_manage = client.allows("placement.manage");
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let action = RwSignal::new(String::new());
    let current = authority.clone().unwrap_or_default();
    let request_version = authority
        .as_ref()
        .map(|value| value.resource_version.clone());
    let plan_client = client.clone();
    let request_surface = surface;
    let on_action = Callback::new(move |selected: &'static str| {
        action.set(selected.to_string());
        let idempotency_key = idempotency_key(&format!("write-authority-{selected}"));
        let request = aos_proto_types::SurfaceMutationRequest {
            surface: Some(request_surface.clone()),
            expected_resource_version: request_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        let path = match selected {
            "cancel" => aos_proto_types::TOPOLOGY_SERVICE_PLAN_CANCEL_PLACEMENT_PROMOTION_PATH,
            "remove" => aos_proto_types::TOPOLOGY_SERVICE_PLAN_REMOVE_WRITE_AUTHORITY_PATH,
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
            "cancel" => aos_proto_types::TOPOLOGY_SERVICE_CANCEL_PLACEMENT_PROMOTION_PATH,
            "remove" => aos_proto_types::TOPOLOGY_SERVICE_REMOVE_WRITE_AUTHORITY_PATH,
            _ => return,
        };
        let client = client.clone();
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
    let cancel_action = on_action.clone();
    let cancel = move |_| cancel_action.run("cancel");
    let remove = move |_| on_action.run("remove");
    let exists = authority.is_some();
    let promotion_pending =
        exists && current.desired_placement_name != current.observed_placement_name;

    view! {
        {if exists { view! { <div class="resource-identity"><div><span>"Mode"</span><strong>{current.mode}</strong></div><div><span>"Desired writer"</span><code>{current.desired_placement_name}</code></div><div><span>"Observed writer"</span><code>{current.observed_placement_name}</code></div><div><span>"Desired generation"</span><strong>{current.desired_generation}</strong></div><div><span>"Observed generation"</span><strong>{current.observed_generation}</strong></div><div><span>"Reconciliation"</span><StatusBadge state=current.reconciliation_state.clone() positive=current.reconciliation_state == "ready"/></div><div><span>"Incarnation"</span><code>{current.incarnation_id}</code></div></div>{can_manage.then(|| view! { <div class="form-actions">{promotion_pending.then(|| view! { <button class="secondary-button" type="button" disabled=move || busy.get() on:click=cancel>"Review promotion cancellation"</button> })}<button class="danger-button" type="button" disabled=move || busy.get() on:click=remove>"Review read-only transition"</button></div> })} }.into_any() } else { view! { <p class="muted">"This surface is explicitly read-only and has no write-authority incarnation."</p> }.into_any() }}<PlanReview pending=pending error=error busy=busy on_apply=on_apply/>
    }
}

#[component]
fn PlacementOperations(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    placement: aos_proto_types::Placement,
) -> impl IntoView {
    let source = RwSignal::new(String::new());
    let action = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = source.get();
        },
        pending,
        error,
    );
    let scan_client = client.clone();
    let scan_surface = surface.clone();
    let scan_placement = placement.clone();
    let on_scan = move |_| {
        action.set("scan".to_string());
        let idempotency_key = idempotency_key("placement-scan");
        let request = aos_proto_types::PlanScanPlacementRequest {
            surface: Some(scan_surface.clone()),
            placement_name: scan_placement.name.clone(),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: scan_placement.resource_version.clone(),
        };
        plan(
            scan_client.clone(),
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_SCAN_PLACEMENT_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
            Some(draft_epoch),
        );
    };
    let repair_client = client.clone();
    let repair_surface = surface;
    let repair_placement = placement;
    let on_repair = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
        action.set("repair".to_string());
        let idempotency_key = idempotency_key("placement-repair");
        let request = aos_proto_types::PlanRepairPlacementRequest {
            surface: Some(repair_surface.clone()),
            placement_name: repair_placement.name.clone(),
            source_placement_name: source.get_untracked().trim().to_string(),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: repair_placement.resource_version.clone(),
        };
        plan(
            repair_client.clone(),
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_REPAIR_PLACEMENT_PATH,
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
        let path = match action.get_untracked().as_str() {
            "scan" => aos_proto_types::TOPOLOGY_SERVICE_SCAN_PLACEMENT_PATH,
            "repair" => aos_proto_types::TOPOLOGY_SERVICE_REPAIR_PLACEMENT_PATH,
            _ => return,
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::OperationResponse>(path, &reviewed.topology_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="subworkflow"><h4>"Controller operations"</h4><p>"Scan inventory evidence or repair this placement from an optional known-good source."</p><div class="form-actions"><button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_scan>"Review scan"</button></div><form class="stacked-form" on:submit=on_repair><label><span>"Repair source placement (optional)"</span><input prop:value=move || source.get() on:input=move |event| source.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review repair"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section>
    }
}

#[component]
fn PlacementReplication(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    placements: Vec<aos_proto_types::Placement>,
) -> impl IntoView {
    view! {
        <section class="panel editor-panel"><p class="section-kicker">"Replica setup"</p><h2>"Copy data to a replica"</h2><p>"Choose an existing source and destination. Review the copy, then inspect its operation and destination evidence before promoting it to writer."</p><ReplicationForm client=client surface=surface placements=placements/></section>
    }
}

#[component]
fn ReplicationForm(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    placements: Vec<aos_proto_types::Placement>,
) -> impl IntoView {
    let initial = placements
        .first()
        .map(|value| value.name.clone())
        .unwrap_or_default();
    let source = RwSignal::new(initial.clone());
    let destination = RwSignal::new(initial);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = (source.get(), destination.get());
        },
        pending,
        error,
    );
    let request_placements = placements.clone();
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
        let source_name = source.get_untracked();
        let destination_name = destination.get_untracked();
        if source_name == destination_name {
            error.set(Some(
                "Source and destination placements must differ".to_string(),
            ));
            return;
        }
        let Some(version) = request_placements
            .iter()
            .find(|placement| placement.name == destination_name)
            .map(|placement| placement.resource_version.clone())
        else {
            error.set(Some("Select a current destination placement".to_string()));
            return;
        };
        let idempotency_key = idempotency_key("placement-replicate");
        let request = aos_proto_types::PlanReplicatePlacementRequest {
            surface: Some(surface.clone()),
            source_placement_name: source_name,
            destination_placement_name: destination_name,
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: version,
        };
        plan(
            plan_client.clone(),
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_REPLICATE_PLACEMENT_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
            Some(draft_epoch),
        );
    };
    let on_apply = apply::<aos_proto_types::OperationResponse>(
        client,
        aos_proto_types::TOPOLOGY_SERVICE_REPLICATE_PLACEMENT_PATH,
        pending,
        error,
        busy,
    );

    view! {
        <form class="editor-form" on:submit=on_plan><label><span>"Source"</span><select prop:value=move || source.get() on:change=move |event| source.set(event_target_value(&event))>{placements.iter().map(|placement| view! { <option value=placement.name.clone()>{placement.name.clone()}</option> }).collect_view()}</select></label><label><span>"Destination"</span><select prop:value=move || destination.get() on:change=move |event| destination.set(event_target_value(&event))>{placements.iter().map(|placement| view! { <option value=placement.name.clone()>{placement.name.clone()}</option> }).collect_view()}</select></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get() || placements.len() < 2>"Review replication"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/>
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
    pending.set(None);
    busy.set(true);
    error.set(None);
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
                    .is_none_or(|(epoch, planned)| epoch.get_untracked() == *planned) =>
            {
                pending.set(Some(reviewed))
            }
            Ok(_) => {}
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
fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}
fn reload() {
    crate::app::refresh();
}
