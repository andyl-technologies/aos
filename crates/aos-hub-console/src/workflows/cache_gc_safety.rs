//! GC candidate-plan inspection and first-sweep acknowledgement.
//!
//! These controls make the fail-closed first-sweep interlock visible. The
//! operator can inspect the exact immutable candidate manifest before creating
//! and applying a separate acknowledgement plan.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HashValue, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

/// Renders immutable plan inspection and first-sweep acknowledgement controls.
#[component]
pub(super) fn GcSafetyControls(
    client: ApiClient,
    cache_id: String,
    generation_version: String,
) -> impl IntoView {
    view! {
        <div class="workflow-stack">
            <GcPlanInspector client=client.clone() cache_id=cache_id.clone()/>
            <FirstSweepAcknowledgement client=client cache_id=cache_id generation_version=generation_version/>
        </div>
    }
}

#[component]
fn GcPlanInspector(client: ApiClient, cache_id: String) -> impl IntoView {
    let plan_id = RwSignal::new(String::new());
    let plan = RwSignal::new(None::<aos_proto_types::CacheGcPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let plan_id = plan_id.get_untracked().trim().to_string();
        if plan_id.is_empty() {
            error.set(Some("GC plan ID is required".to_string()));
            return;
        }
        let client = client.clone();
        let cache_id = cache_id.clone();
        plan.set(None);
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::CacheGcPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_CACHE_GC_PLAN_PATH,
                    &aos_proto_types::GetCacheGcPlanRequest { cache_id, plan_id },
                )
                .await
            {
                Ok(response) => match response.plan {
                    Some(value) => plan.set(Some(value)),
                    None => error.set(Some("The Hub omitted the GC plan".to_string())),
                },
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Frozen deletion manifest"</p>
                    <h2>"Inspect a GC plan"</h2>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label>
                    <span>"GC plan ID"</span>
                    <input required prop:value=move || plan_id.get() on:input=move |event| plan_id.set(event_target_value(&event))/>
                </label>
                <div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get()>"Load exact plan"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || plan.get().map(|plan| view! { <GcPlanDetail plan=plan/> })}
        </section>
    }
}

#[component]
pub(super) fn GcPlanDetail(plan: aos_proto_types::CacheGcPlan) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{plan.plan_id}</strong><HashValue value=plan.candidate_manifest_hash/></div>
                <StatusBadge state=format!("epoch {}", plan.gc_epoch) positive=plan.coverage_failures.is_empty()/>
            </div>
            <div class="resource-identity">
                <div><span>"Policy version"</span><strong>{plan.policy_version}</strong></div>
                <div><span>"Root set"</span><code>{plan.root_set_version}</code></div>
                <div><span>"Object set"</span><code>{plan.object_set_version}</code></div>
                <div><span>"Topology"</span><code>{plan.topology_version}</code></div>
                <div><span>"Expires"</span><strong>{plan.expires_at}</strong></div>
            </div>
            <h4>{format!("{} object candidates", plan.candidates.len())}</h4>
            <div class="compact-list">
                {plan.candidates.into_iter().map(|candidate| view! {
                    <div class="compact-list-row">
                        <HashValue value=candidate.store_hash/>
                        <span>{format!("{} logical bytes", candidate.logical_bytes)}</span>
                        {(!candidate.blocking_reasons.is_empty()).then(|| view! {
                            <span>{format!("blocked: {}", candidate.blocking_reasons.join(", "))}</span>
                        })}
                    </div>
                }).collect_view()}
            </div>
            <h4>{format!("{} placement actions", plan.placement_actions.len())}</h4>
            <div class="compact-list">
                {plan.placement_actions.into_iter().map(|action| view! {
                    <div class="compact-list-row">
                        <code>{action.placement_id}</code><span>{action.action}</span><HashValue value=action.store_hash/>
                    </div>
                }).collect_view()}
            </div>
            {(!plan.coverage_failures.is_empty()).then(|| view! {
                <div class="warning-list">
                    <h4>"Coverage failures"</h4>
                    {plan.coverage_failures.into_iter().map(|failure| view! { <p>{failure}</p> }).collect_view()}
                </div>
            })}
        </article>
    }
}

#[component]
fn FirstSweepAcknowledgement(
    client: ApiClient,
    cache_id: String,
    generation_version: String,
) -> impl IntoView {
    let gc_plan_id = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let plan_version = generation_version.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let gc_plan = gc_plan_id.get_untracked().trim().to_string();
        if gc_plan.is_empty() {
            error.set(Some("GC plan ID is required".to_string()));
            return;
        }
        let key = idempotency_key("gc-first-sweep-ack");
        let request = aos_proto_types::PlanAcknowledgeCacheGcFirstSweepRequest {
            cache_id: cache_id.clone(),
            gc_plan_id: gc_plan,
            expected_resource_version: plan_version.clone(),
            idempotency_key: key.clone(),
        };
        let client = plan_client.clone();
        error.set(None);
        pending.set(None);
        busy.set(true);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_ACKNOWLEDGE_CACHE_GC_FIRST_SWEEP_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, key));
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
                .call::<_, aos_proto_types::CacheGcGenerationResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_ACKNOWLEDGE_CACHE_GC_FIRST_SWEEP_PATH,
                    &reviewed.cache_plan_apply(),
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
        <section class="panel resource-panel danger-subworkflow">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"One-time safety interlock"</p>
                    <h2>"Acknowledge the first sweep"</h2>
                    <p>"Acknowledge only after inspecting the exact candidate manifest above. Later plans remain version-bound but do not repeat this bootstrap gate."</p>
                </div>
            </div>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"GC plan ID"</span><input required prop:value=move || gc_plan_id.get() on:input=move |event| gc_plan_id.set(event_target_value(&event))/></label>
                <div class="compact-list-row"><span>"Bound GC resource version"</span><code>{generation_version}</code></div>
                <div class="form-actions"><button class="danger-button" type="submit" disabled=move || busy.get()>"Review first-sweep acknowledgement"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! {
                <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/>
            })}
        </section>
    }
}

fn reload() {
    crate::app::refresh();
}
