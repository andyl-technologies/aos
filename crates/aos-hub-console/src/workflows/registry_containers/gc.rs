//! Reviewable registry-scoped OCI garbage collection.
//!
//! The browser loads every model through authenticated Connect calls. Planning
//! freezes the retention policy, mutation epoch, root set, topology, and
//! placement inventory before the destructive apply control is rendered.

use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::app::refresh;
use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{
    container_gc_plan_is_applicable, effective_container_retention_version, idempotency_key,
    reviewed_plan_resource_version, PendingPlan,
};
use crate::transport::ApiClient;

use super::format_bytes;

async fn plan_registry_purge_fence(
    client: &ApiClient,
    request: &aos_proto_types::PlanContainerRegistryPurgeFenceRequest,
) -> Result<aos_proto_types::TopologyPlanResponse, crate::transport::TransportError> {
    client
        .call::<_, aos_proto_types::TopologyPlanResponse>(
            aos_proto_types::CONTAINER_SERVICE_PLAN_CONTAINER_REGISTRY_PURGE_FENCE_PATH,
            request,
        )
        .await
}

async fn apply_registry_purge_fence(
    client: &ApiClient,
    request: &aos_proto_types::ApplyContainerRegistryPurgeFenceRequest,
) -> Result<aos_proto_types::ContainerRegistryPurgeFenceResponse, crate::transport::TransportError>
{
    client
        .call::<_, aos_proto_types::ContainerRegistryPurgeFenceResponse>(
            aos_proto_types::CONTAINER_SERVICE_APPLY_CONTAINER_REGISTRY_PURGE_FENCE_PATH,
            request,
        )
        .await
}

async fn get_registry_purge_fence(
    client: &ApiClient,
    plan_id: String,
) -> Result<aos_proto_types::ContainerRegistryPurgeFenceResponse, crate::transport::TransportError>
{
    client
        .call::<_, aos_proto_types::ContainerRegistryPurgeFenceResponse>(
            aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_REGISTRY_PURGE_FENCE_PATH,
            &aos_proto_types::GetContainerRegistryPurgeFenceRequest { plan_id },
        )
        .await
}

/// Renders GC planning, blockers, planned impact, and durable run history.
#[component]
pub(super) fn ContainerGc(client: ApiClient, registry: String) -> impl IntoView {
    let policy_client = client.clone();
    let policy_registry = registry.clone();
    let policy = LocalResource::new(move || {
        let client = policy_client.clone();
        let registry = policy_registry.clone();
        async move {
            client
                .call::<_, aos_proto_types::ContainerRetentionPolicyResponse>(
                    aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_RETENTION_POLICY_PATH,
                    &aos_proto_types::GetContainerRetentionPolicyRequest { registry },
                )
                .await
        }
    });
    let planner_client = client.clone();
    let planner_registry = registry.clone();

    view! {
        <div class="workflow-stack container-gc-workflow">
            <Suspense fallback=move || view! { <section class="panel"><p class="loading-row">"Loading container GC fence…"</p></section> }>
                {move || {
                    let client = planner_client.clone();
                    let registry = planner_registry.clone();
                    Suspend::new(async move {
                        match policy.await.as_ref() {
                            Ok(response) => match response.policy.clone() {
                                Some(policy) => view! {
                                    <ContainerGcPlanner client=client registry=registry policy_version=effective_container_retention_version(&policy.resource_version)/>
                                }.into_any(),
                                None => view! { <InlineError detail="The Hub omitted the container retention fence.".to_string()/> }.into_any(),
                            },
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
            <ContainerUntrackedInventory client=client.clone() registry=registry.clone()/>
            <ContainerRegistryPurgeFencePanel client=client.clone() registry=registry.clone()/>
            <ContainerGcRuns client=client registry=registry/>
        </div>
    }
}

#[component]
fn ContainerRegistryPurgeFencePanel(client: ApiClient, registry: String) -> impl IntoView {
    let action = RwSignal::new("begin".to_string());
    let expected_version = RwSignal::new(String::new());
    let status_plan_id = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let apply_version = RwSignal::new(None::<String>);
    let status = RwSignal::new(None::<aos_proto_types::ContainerRegistryPurgeFence>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let can_manage = client.allows("registry.configure");

    let plan_client = client.clone();
    let plan_registry = registry.clone();
    let on_plan = move |_| {
        let version = expected_version.get_untracked().trim().to_string();
        if version.is_empty() {
            error.set(Some(
                "Enter the registry version for Begin or current fence version for Abort."
                    .to_string(),
            ));
            return;
        }
        let selected_action = match action.get_untracked().as_str() {
            "begin" => aos_proto_types::ContainerRegistryPurgeFenceAction::Begin as i32,
            "abort" => aos_proto_types::ContainerRegistryPurgeFenceAction::Abort as i32,
            _ => {
                error.set(Some("Select Begin or Abort.".to_string()));
                return;
            }
        };
        let client = plan_client.clone();
        let key = idempotency_key("container-registry-purge-fence");
        let request = aos_proto_types::PlanContainerRegistryPurgeFenceRequest {
            registry: plan_registry.clone(),
            action: selected_action,
            expected_resource_version: version,
            idempotency_key: key.clone(),
        };
        pending.set(None);
        apply_version.set(None);
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match plan_registry_purge_fence(&client, &request).await {
                Ok(response) => {
                    match reviewed_plan_resource_version(&response).and_then(|version| {
                        PendingPlan::from_response(response, key).map(|plan| (version, plan))
                    }) {
                        Ok((version, reviewed)) => {
                            status_plan_id.set(reviewed.plan.plan_id.clone());
                            apply_version.set(Some(version));
                            pending.set(Some(reviewed));
                        }
                        Err(detail) => error.set(Some(detail)),
                    }
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    let apply_client = client.clone();
    let on_apply = Callback::new(move |()| {
        let (Some(reviewed), Some(expected_resource_version)) =
            (pending.get_untracked(), apply_version.get_untracked())
        else {
            return;
        };
        let client = apply_client.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            let request = aos_proto_types::ApplyContainerRegistryPurgeFenceRequest {
                plan_id: reviewed.plan.plan_id,
                idempotency_key: reviewed.idempotency_key,
                confirmation_hash: reviewed.plan.confirmation_hash,
                expected_resource_version,
            };
            match apply_registry_purge_fence(&client, &request).await {
                Ok(response) => match response.fence {
                    Some(fence) => {
                        status_plan_id.set(fence.plan_id.clone());
                        status.set(Some(fence));
                        pending.set(None);
                        apply_version.set(None);
                    }
                    None => error.set(Some("The Hub omitted the purge-fence status.".to_string())),
                },
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    let status_client = client;
    let on_status = move |_| {
        let plan_id = status_plan_id.get_untracked().trim().to_string();
        if plan_id.is_empty() {
            error.set(Some("Enter a purge-fence plan ID.".to_string()));
            return;
        }
        let client = status_client.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match get_registry_purge_fence(&client, plan_id).await {
                Ok(response) => match response.fence {
                    Some(fence) => status.set(Some(fence)),
                    None => error.set(Some("The Hub omitted the purge-fence status.".to_string())),
                },
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel danger-panel container-registry-purge-fence">
            <div class="section-heading"><div><p class="section-kicker">"Final registry purge"</p><h2>"Registry writer fence"</h2><p>"Begin blocks new OCI writes. Final registry deletion remains a separate reviewed operation and requires fresh complete empty inventories captured after this exact fence."</p></div></div>
            {can_manage.then(|| view! {
                <div class="form-grid">
                    <label><span>"Action"</span><select prop:value=move || action.get() on:change=move |event| action.set(event_target_value(&event))><option value="begin">"Begin"</option><option value="abort">"Abort"</option></select></label>
                    <label><span>"Expected version"</span><input prop:value=move || expected_version.get() on:input=move |event| expected_version.set(event_target_value(&event)) placeholder="Registry RV for Begin; fence RV for Abort"/></label>
                </div>
                <button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Create purge-fence plan"</button>
            })}
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| { pending.set(None); apply_version.set(None); })/> })}
            <div class="compact-list-row"><input prop:value=move || status_plan_id.get() on:input=move |event| status_plan_id.set(event_target_value(&event)) placeholder="Purge-fence plan ID"/><button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_status>"Load status"</button></div>
            {move || status.get().map(|fence| {
                let blockers = fence.blockers.unwrap_or_default();
                view! {
                    <div class="subworkflow purge-fence-status">
                        <div class="compact-list-row"><strong>{fence.fence_state.clone()}</strong><StatusBadge state=if fence.post_fence_inventory_ready { "ready".to_string() } else { "blocked".to_string() } positive=fence.post_fence_inventory_ready/></div>
                        <div class="resource-identity"><div><span>"Plan"</span><code>{fence.plan_id}</code></div><div><span>"Plan version"</span><code>{fence.plan_resource_version}</code></div><div><span>"Fence version"</span><code>{fence.fence_resource_version}</code></div><div><span>"Mutation epoch"</span><code>{fence.captured_mutation_epoch}</code></div><div><span>"Repositories"</span><strong>{blockers.repositories}</strong></div><div><span>"Catalog objects"</span><strong>{blockers.catalog_objects}</strong></div><div><span>"Active sessions"</span><strong>{blockers.active_sessions}</strong></div><div><span>"GC work"</span><strong>{blockers.gc_work}</strong></div><div><span>"Tracked provider objects"</span><strong>{blockers.tracked_provider_objects}</strong></div><div><span>"Untracked provider objects"</span><strong>{blockers.untracked_provider_objects}</strong></div><div><span>"Stale / missing inventories"</span><strong>{blockers.stale_or_missing_inventories}</strong></div><div><span>"Snapshot references"</span><strong>{blockers.snapshot_references}</strong></div></div>
                        <p class="muted">"Only ready status permits the separately reviewed final DeleteRegistry operation. Abort invalidates this readiness."</p>
                    </div>
                }
            })}
        </section>
    }
}

#[component]
fn ContainerUntrackedInventory(client: ApiClient, registry: String) -> impl IntoView {
    let list_client = client.clone();
    let list_registry = registry.clone();
    let inventory = LocalResource::new(move || {
        let client = list_client.clone();
        let registry = list_registry.clone();
        async move {
            client
                .call::<_, aos_proto_types::ListContainerUntrackedInventoryResponse>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_UNTRACKED_INVENTORY_PATH,
                    &aos_proto_types::ListContainerUntrackedInventoryRequest {
                        registry,
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await
        }
    });
    let can_manage = client.allows("registry.configure");

    view! {
        <section class="panel danger-panel container-untracked-inventory">
            <div class="section-heading"><div><p class="section-kicker">"Provider reconciliation"</p><h2>"Untracked provider objects"</h2><p>"Only complete current-head inventory is shown. Repair uses a reviewed exact conditional delete and never adopts or deletes bytes directly from this view."</p></div></div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading untracked provider inventory…"</p> }>
                {move || {
                    let client = client.clone();
                    let registry = registry.clone();
                    Suspend::new(async move {
                        match inventory.await.as_ref() {
                            Ok(response) if response.objects.is_empty() => view! { <p class="muted">"No untracked objects in current inventory heads."</p> }.into_any(),
                            Ok(response) => {
                                let epoch = response.inventory_epoch.clone();
                                let more = !response.next_page_token.is_empty();
                                view! {
                                    <p class="muted">{format!("{} loaded{} · inventory epoch {}", response.objects.len(), if more { " · more available through the CLI" } else { "" }, epoch)}</p>
                                    <div class="binding-list">{response.objects.iter().cloned().map(|object| view! { <ContainerUntrackedObjectCard client=client.clone() registry=registry.clone() inventory_epoch=epoch.clone() object=object can_manage=can_manage/> }).collect_view()}</div>
                                }.into_any()
                            }
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
        </section>
    }
}

#[component]
fn ContainerUntrackedObjectCard(
    client: ApiClient,
    registry: String,
    inventory_epoch: String,
    object: aos_proto_types::ContainerUntrackedInventoryObject,
    can_manage: bool,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let apply_version = RwSignal::new(None::<String>);
    let repair_status = RwSignal::new(None::<aos_proto_types::ContainerUntrackedRepair>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let plan_registry = registry.clone();
    let plan_object = object.clone();
    let plan_epoch = inventory_epoch.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let key = idempotency_key("container-untracked-repair");
        let request = aos_proto_types::PlanRepairContainerUntrackedObjectRequest {
            registry: plan_registry.clone(),
            placement_id: plan_object.placement_id,
            inventory_generation_id: plan_object.inventory_generation_id.clone(),
            object_key: plan_object.object_key.clone(),
            expected_resource_version: plan_epoch.clone(),
            idempotency_key: key.clone(),
        };
        pending.set(None);
        apply_version.set(None);
        repair_status.set(None);
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::CONTAINER_SERVICE_PLAN_REPAIR_CONTAINER_UNTRACKED_OBJECT_PATH,
                    &request,
                )
                .await
            {
                Ok(response) => {
                    match reviewed_plan_resource_version(&response).and_then(|version| {
                        PendingPlan::from_response(response, key).map(|plan| (version, plan))
                    }) {
                        Ok((version, reviewed)) => {
                            apply_version.set(Some(version));
                            pending.set(Some(reviewed));
                        }
                        Err(detail) => error.set(Some(detail)),
                    }
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    let apply_client = client.clone();
    let on_apply = Callback::new(move |()| {
        let (Some(reviewed), Some(expected_resource_version)) =
            (pending.get_untracked(), apply_version.get_untracked())
        else {
            return;
        };
        let client = apply_client.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::OperationResponse>(
                    aos_proto_types::CONTAINER_SERVICE_REPAIR_CONTAINER_UNTRACKED_OBJECT_PATH,
                    &aos_proto_types::RepairContainerUntrackedObjectRequest {
                        plan_id: reviewed.plan.plan_id,
                        idempotency_key: reviewed.idempotency_key,
                        confirmation_hash: reviewed.plan.confirmation_hash,
                        expected_resource_version,
                    },
                )
                .await
            {
                Ok(response) => {
                    let Some(operation) = response.operation else {
                        error.set(Some(
                            "The Hub omitted the repair operation identity.".to_string(),
                        ));
                        busy.set(false);
                        return;
                    };
                    match client
                        .call::<_, aos_proto_types::ContainerUntrackedRepairResponse>(
                            aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_UNTRACKED_REPAIR_PATH,
                            &aos_proto_types::GetContainerUntrackedRepairRequest {
                                plan_id: operation.operation_id,
                            },
                        )
                        .await
                    {
                        Ok(response) => match response.repair {
                            Some(repair) => {
                                repair_status.set(Some(repair));
                                pending.set(None);
                                apply_version.set(None);
                            }
                            None => error.set(Some(
                                "The Hub omitted the durable repair status.".to_string(),
                            )),
                        },
                        Err(failure) => error.set(Some(failure.to_string())),
                    }
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    let status_client = client;
    let on_refresh_status = Callback::new(move |()| {
        let Some(plan_id) = repair_status.get_untracked().map(|repair| repair.plan_id) else {
            return;
        };
        let client = status_client.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ContainerUntrackedRepairResponse>(
                    aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_UNTRACKED_REPAIR_PATH,
                    &aos_proto_types::GetContainerUntrackedRepairRequest { plan_id },
                )
                .await
            {
                Ok(response) => match response.repair {
                    Some(repair) => repair_status.set(Some(repair)),
                    None => error.set(Some(
                        "The Hub omitted the durable repair status.".to_string(),
                    )),
                },
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <article class="binding-card untracked-object-card">
            <div class="compact-list-row"><div><strong>{object.placement_name}</strong><code>{object.object_key}</code></div><StatusBadge state="untracked".to_string() positive=false/></div>
            <div class="resource-identity"><div><span>"Observed identity"</span><code>{object.observed_hash}</code></div><div><span>"Digest"</span><code>{object.object_digest}</code></div><div><span>"Size"</span><strong>{format_bytes(object.byte_size)}</strong></div><div><span>"Strong ETag"</span><code>{object.strong_etag}</code></div><div><span>"Inventory generation"</span><code>{object.inventory_generation_id}</code></div><div><span>"Inventory digest"</span><code>{object.inventory_digest}</code></div><div><span>"Placement version"</span><code>{object.placement_resource_version}</code></div><div><span>"Binding revision"</span><code>{object.binding_write_revision}</code></div><div><span>"Conditional-delete capability"</span><code>{object.delete_capability_fingerprint}</code></div></div>
            {can_manage.then(|| view! { <button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Create exact repair plan"</button> })}
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| { pending.set(None); apply_version.set(None); })/> })}
            {move || repair_status.get().map(|repair| view! {
                <div class="subworkflow untracked-repair-status">
                    <div class="compact-list-row"><strong>"Durable repair"</strong><StatusBadge state=repair.state.clone() positive=repair.state == "complete"/></div>
                    <div class="resource-identity"><div><span>"Plan / operation"</span><code>{repair.plan_id}</code></div><div><span>"Resource version"</span><code>{repair.resource_version}</code></div><div><span>"Frozen inventory"</span><code>{repair.inventory_generation_id}</code></div><div><span>"Object"</span><code>{repair.object_key}</code></div><div><span>"Last error"</span><code>{repair.last_error}</code></div></div>
                    {repair.evidence.map(|evidence| view! { <div class="notice success"><strong>{evidence.outcome}</strong><code>{evidence.evidence_digest}</code><span>{format!("Confirmed at {}", evidence.confirmed_at)}</span></div> })}
                    <button class="secondary-button" type="button" disabled=move || busy.get() on:click=move |_| on_refresh_status.run(())>"Refresh repair status"</button>
                    <p class="muted">"A fresh complete provider inventory is still required before registry purge."</p>
                </div>
            })}
        </article>
    }
}

#[component]
fn ContainerGcPlanner(
    client: ApiClient,
    registry: String,
    policy_version: String,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let exact = RwSignal::new(None::<aos_proto_types::ContainerGcPlanResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let can_manage = client.allows("registry.configure");
    let plan_client = client.clone();
    let plan_registry = registry.clone();
    let version = policy_version.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let key = idempotency_key("container-gc");
        let request = aos_proto_types::PlanRunContainerGcRequest {
            registry: plan_registry.clone(),
            expected_resource_version: version.clone(),
            idempotency_key: key.clone(),
        };
        pending.set(None);
        exact.set(None);
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ContainerGcPlanResponse>(
                    aos_proto_types::CONTAINER_SERVICE_PLAN_RUN_CONTAINER_GC_PATH,
                    &request,
                )
                .await
            {
                Ok(response) => {
                    let applicable = container_gc_plan_is_applicable(&response);
                    exact.set(Some(response.clone()));
                    if applicable {
                        let topology = aos_proto_types::TopologyPlanResponse {
                            plan: response.plan,
                        };
                        match PendingPlan::from_response(topology, key) {
                            Ok(reviewed) => pending.set(Some(reviewed)),
                            Err(detail) => error.set(Some(detail)),
                        }
                    } else {
                        pending.set(None);
                        if response.blockers.is_empty() {
                            error.set(Some(
                                "The GC generation is not in an applicable planned state."
                                    .to_string(),
                            ));
                        }
                    }
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::OperationResponse>(
                    aos_proto_types::CONTAINER_SERVICE_RUN_CONTAINER_GC_PATH,
                    &reviewed.container_apply(),
                )
                .await
            {
                Ok(_) => refresh(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="panel danger-panel">
            <div class="section-heading"><div><p class="section-kicker">"Inventory-bound deletion"</p><h2>"Container garbage collection"</h2><p>"The Hub must prove a complete placement inventory and revalidate the exact epoch before any conditional deletion begins."</p></div></div>
            <div class="compact-list-row"><span>"Retention policy version"</span><code>{policy_version}</code></div>
            {can_manage.then(|| view! { <button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Create GC plan"</button> })}
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || exact.get().map(|response| view! { <ContainerGcPlanDetail response=response/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| { pending.set(None); exact.set(None); })/> })}
        </section>
    }
}

#[component]
fn ContainerGcPlanDetail(response: aos_proto_types::ContainerGcPlanResponse) -> impl IntoView {
    let run = response.run.unwrap_or_default();
    view! {
        <div class="subworkflow container-gc-plan-detail">
            <div class="resource-identity">
                <div><span>"Generation"</span><code>{run.run_id}</code></div>
                <div><span>"Frozen inventory"</span><strong>{format!("{} · {}", run.inventory_object_count, format_bytes(run.inventory_byte_size))}</strong></div>
                <div><span>"Reachable objects"</span><strong>{run.reachable_object_count}</strong></div>
                <div><span>"Planned objects"</span><strong>{run.candidate_object_count}</strong></div>
                <div><span>"Planned bytes"</span><strong>{format_bytes(run.reclaimable_byte_size)}</strong></div>
                <div><span>"Placement actions"</span><strong>{run.placement_action_count}</strong></div>
                <div><span>"Mutation epoch"</span><code>{run.mutation_epoch}</code></div>
                <div><span>"Expires"</span><strong>{run.expires_at}</strong></div>
            </div>
            <code class="digest-block">{run.plan_digest}</code>
            {(!response.blockers.is_empty()).then(|| view! {
                <div class="notice warning"><strong>"GC is blocked"</strong><ul>{response.blockers.into_iter().map(|blocker| view! { <li><code>{blocker.kind}</code>" — "{blocker.detail}</li> }).collect_view()}</ul></div>
            })}
        </div>
    }
}

#[component]
fn ContainerGcRuns(client: ApiClient, registry: String) -> impl IntoView {
    let selected = RwSignal::new(None::<String>);
    let list_client = client.clone();
    let list_registry = registry.clone();
    let runs = LocalResource::new(move || {
        let client = list_client.clone();
        let registry = list_registry.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListContainerGcRunsResponse, _, _, _>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_GC_RUNS_PATH,
                    move |page_token| aos_proto_types::ListContainerGcRunsRequest {
                        registry: registry.clone(),
                        state: String::new(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.runs, response.next_page_token),
                )
                .await
        }
    });
    let detail_client = client;
    let detail_registry = registry;
    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Durable operations"</p><h2>"Container GC runs"</h2></div></div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading container GC runs…"</p> }>
                {move || Suspend::new(async move {
                    match runs.await.as_ref() {
                        Ok(runs) if runs.is_empty() => view! { <p class="muted">"No container GC runs."</p> }.into_any(),
                        Ok(runs) => view! { <div class="binding-list">{runs.iter().cloned().map(|run| {
                            let run_id = run.run_id.clone();
                            view! {
                                <button type="button" class="binding-card" on:click=move |_| selected.set(Some(run_id.clone()))><div class="compact-list-row"><div><strong>{run.run_id}</strong><code>{run.mutation_epoch}</code></div><StatusBadge state=run.state.clone() positive=run.state == "complete"/></div><div class="resource-identity"><div><span>"Planned"</span><strong>{format!("{} · {}", run.candidate_object_count, format_bytes(run.reclaimable_byte_size))}</strong></div><div><span>"Finalized"</span><strong>{format!("{} · {}", run.deleted_object_count, format_bytes(run.deleted_byte_size))}</strong></div><div><span>"Actions"</span><strong>{run.placement_action_count}</strong></div></div>{(!run.failure.is_empty()).then(|| view! { <InlineError detail=run.failure/> })}</button>
                            }
                        }).collect_view()}</div> }.into_any(),
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
        {move || selected.get().map(|run_id| view! { <ContainerGcRunDetail client=detail_client.clone() registry=detail_registry.clone() run_id=run_id/> })}
    }
}

#[component]
fn ContainerGcRunDetail(client: ApiClient, registry: String, run_id: String) -> impl IntoView {
    let detail = LocalResource::new(move || {
        let client = client.clone();
        let registry = registry.clone();
        let run_id = run_id.clone();
        async move {
            let run = client
                .call::<_, aos_proto_types::ContainerGcRunResponse>(
                    aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_GC_RUN_PATH,
                    &aos_proto_types::GetContainerGcRunRequest {
                        registry: registry.clone(),
                        run_id: run_id.clone(),
                    },
                )
                .await?;
            let candidates = client
                .call::<_, aos_proto_types::ListContainerGcCandidatesResponse>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_GC_CANDIDATES_PATH,
                    &aos_proto_types::ListContainerGcCandidatesRequest {
                        registry: registry.clone(),
                        run_id: run_id.clone(),
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await?;
            let blockers = client
                .call::<_, aos_proto_types::ListContainerGcBlockersResponse>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_GC_BLOCKERS_PATH,
                    &aos_proto_types::ListContainerGcBlockersRequest {
                        registry: registry.clone(),
                        run_id: run_id.clone(),
                    },
                )
                .await?;
            let actions = client
                .call::<_, aos_proto_types::ListContainerGcPlacementActionsResponse>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_GC_PLACEMENT_ACTIONS_PATH,
                    &aos_proto_types::ListContainerGcPlacementActionsRequest {
                        registry,
                        run_id,
                        state: String::new(),
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await?;
            Ok::<_, crate::transport::TransportError>((run, candidates, blockers, actions))
        }
    });
    view! {
        <section class="panel resource-panel container-gc-run-detail">
            <div class="section-heading"><div><p class="section-kicker">"Exact deletion evidence"</p><h2>"GC run detail"</h2><p>"Candidate and placement-action previews are bounded to the first 100 records; use the CLI for cursor continuation."</p></div></div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading GC evidence…"</p> }>
                {move || Suspend::new(async move {
                    match detail.await.as_ref() {
                        Ok((run, candidates, blockers, actions)) => {
                            let run = run.run.clone().unwrap_or_default();
                            view! {
                                <div class="resource-identity"><div><span>"Generation"</span><code>{run.run_id}</code></div><div><span>"Root set"</span><code>{run.root_set_digest}</code></div><div><span>"Inventory"</span><code>{run.placement_inventory_digest}</code></div><div><span>"Topology"</span><code>{run.topology_digest}</code></div></div>
                                {(!blockers.blockers.is_empty()).then(|| view! { <div class="notice warning"><strong>"Blockers"</strong><ul>{blockers.blockers.iter().cloned().map(|blocker| view! { <li><code>{blocker.kind}</code>" — "{blocker.detail}</li> }).collect_view()}</ul></div> })}
                                <div class="subworkflow-grid"><div class="subworkflow"><h3>"Candidate preview"</h3><p>{format!("{} loaded{}", candidates.candidates.len(), if candidates.next_page_token.is_empty() { "" } else { " · more available" })}</p><ul>{candidates.candidates.iter().cloned().map(|candidate| view! { <li><code>{candidate.digest}</code>" · "{format_bytes(candidate.byte_size)}</li> }).collect_view()}</ul></div><div class="subworkflow"><h3>"Placement actions"</h3><p>{format!("{} loaded{}", actions.actions.len(), if actions.next_page_token.is_empty() { "" } else { " · more available" })}</p><ul>{actions.actions.iter().cloned().map(|action| view! { <li><code>{action.placement_name}</code>" · "{action.state}" · "<code>{action.digest}</code><span class="muted">{format!("{} · ETag {} · binding revision {} · credential generation {} · version {}", action.object_key, action.expected_strong_etag, action.binding_write_revision, action.delete_credential_generation, action.resource_version)}</span></li> }).collect_view()}</ul></div></div>
                            }.into_any()
                        }
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}
