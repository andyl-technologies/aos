//! Cache garbage-collection policy and execution workflows.
//!
//! GC is deliberately staged. Policy edits use reviewed mutations, while a
//! sweep receives a separately reviewed immutable candidate plan before any
//! object or placement deletion can begin.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, watch_draft, PendingPlan};
use crate::transport::ApiClient;

use super::cache_gc_jobs::GcDeletionJobs;
use super::cache_gc_safety::{GcPlanDetail, GcSafetyControls};

/// Renders GC policy, planning controls, run history, and deletion jobs.
#[component]
pub(super) fn CacheGcWorkflow(client: ApiClient, cache_id: String) -> impl IntoView {
    let policy_client = client.clone();
    let policy_cache = cache_id.clone();
    let policy = LocalResource::new(move || {
        let client = policy_client.clone();
        let cache_id = policy_cache.clone();
        async move {
            client
                .call::<_, aos_proto_types::GetCacheGcPolicyResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_CACHE_GC_POLICY_PATH,
                    &aos_proto_types::GetCacheGcPolicyRequest { cache_id },
                )
                .await
        }
    });
    let editor_client = client.clone();
    let editor_cache = cache_id.clone();

    view! {
        <div class="workflow-stack">
            <Suspense fallback=move || view! { <section class="panel"><p class="loading-row">"Loading GC policy…"</p></section> }>
                {move || {
                    let client = editor_client.clone();
                    let cache_id = editor_cache.clone();
                    Suspend::new(async move {
                        match policy.await.as_ref() {
                            Ok(response) => view! {
                                <GcConfiguredControls client=client cache_id=cache_id response=response.clone()/>
                            }
                            .into_any(),
                            Err(failure) => view! { <section class="panel"><InlineError detail=failure.to_string()/></section> }.into_any(),
                        }
                    })
                }}
            </Suspense>
            <GcRuns client=client.clone() cache_id=cache_id.clone()/>
            <details class="panel advanced-controls"><summary>"Inspect or recover deletion jobs"</summary>
                <GcDeletionJobs client=client cache_id=cache_id/>
            </details>
        </div>
    }
}

#[component]
fn GcConfiguredControls(
    client: ApiClient,
    cache_id: String,
    response: aos_proto_types::GetCacheGcPolicyResponse,
) -> impl IntoView {
    let policy = response.policy.unwrap_or_default();
    let generation = response.generation.unwrap_or_default();
    let generation_version = generation.resource_version.clone();
    let acknowledgement_required = generation.state == "first_sweep_required";
    let generation_label = if acknowledgement_required {
        "First sweep needs acknowledgement"
    } else if generation.state == "enabled" {
        "Sweeps enabled"
    } else {
        "Unknown GC state"
    };
    let exact_plan = RwSignal::new(None::<aos_proto_types::CacheGcPlan>);

    view! {
        <GcPolicyEditor client=client.clone() cache_id=cache_id.clone() policy=policy/>
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Current concurrency boundary"</p><h2>"GC generation"</h2><p>"Every sweep and acknowledgement below is bound to this generation. Changing policy creates a new review boundary before deletion work can begin."</p></div></div>
            <div class="compact-list-row gc-generation-status">
                <div><strong>"GC concurrency fence"</strong><code>{generation_version.clone()}</code></div>
                <StatusBadge state=generation_label.to_string() positive=generation.state == "enabled"/>
            </div>
        </section>
        <GcPlanner client=client.clone() cache_id=cache_id.clone() version=generation_version.clone() exact_plan=exact_plan/>
        <GcSafetyControls client=client cache_id=cache_id generation_version=generation_version exact_plan=exact_plan acknowledgement_required=acknowledgement_required/>
    }
}

#[component]
fn GcPolicyEditor(
    client: ApiClient,
    cache_id: String,
    policy: aos_proto_types::CacheGcPolicy,
) -> impl IntoView {
    let summary = policy.clone();
    let grace = RwSignal::new(policy.unreferenced_grace_seconds.to_string());
    let max_bytes = RwSignal::new(
        policy
            .soft_max_bytes
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    let max_objects = RwSignal::new(
        policy
            .soft_max_objects
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    let schedule = RwSignal::new(policy.schedule.clone());
    let concurrency = RwSignal::new(policy.deletion_concurrency.to_string());
    let retry_initial = RwSignal::new(policy.retry_initial_seconds.to_string());
    let retry_max = RwSignal::new(policy.retry_max_seconds.to_string());
    let retry_attempts = RwSignal::new(policy.retry_max_attempts.to_string());
    let tombstone_retention = RwSignal::new(policy.tombstone_retention_seconds.to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let version = policy.resource_version;
    let display_version = version.clone();
    let draft_epoch = watch_draft(
        move || {
            let _ = (
                grace.get(),
                max_bytes.get(),
                max_objects.get(),
                schedule.get(),
                concurrency.get(),
                retry_initial.get(),
                retry_max.get(),
                retry_attempts.get(),
                tombstone_retention.get(),
            );
        },
        pending,
        error,
    );
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let desired = match parse_policy(
            &grace.get_untracked(),
            &max_bytes.get_untracked(),
            &max_objects.get_untracked(),
            &schedule.get_untracked(),
            &concurrency.get_untracked(),
            &retry_initial.get_untracked(),
            &retry_max.get_untracked(),
            &retry_attempts.get_untracked(),
            &tombstone_retention.get_untracked(),
        ) {
            Ok(desired) => desired,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let key = idempotency_key("cache-gc-policy");
        let request = aos_proto_types::PlanSetCacheGcPolicyRequest {
            cache_id: cache_id.clone(),
            desired: Some(desired),
            expected_resource_version: version.clone(),
            idempotency_key: key.clone(),
            update_mask: vec![
                "unreferenced_grace_seconds",
                "soft_max_bytes",
                "soft_max_objects",
                "schedule",
                "deletion_concurrency",
                "retry_initial_seconds",
                "retry_max_seconds",
                "retry_max_attempts",
                "tombstone_retention_seconds",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        };
        let client = plan_client.clone();
        error.set(None);
        pending.set(None);
        busy.set(true);
        let planned_epoch = draft_epoch.get_untracked();
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_SET_CACHE_GC_POLICY_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, key));
            match result {
                Ok(reviewed) if draft_epoch.get_untracked() == planned_epoch => {
                    pending.set(Some(reviewed))
                }
                Ok(_) => {}
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
                .call::<_, aos_proto_types::GetCacheGcPolicyResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_SET_CACHE_GC_POLICY_PATH,
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
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Deletion policy"</p>
                    <h2>"Garbage collection"</h2>
                    <p>"Soft limits never override live roots, leases, required coverage, or the unreferenced grace period."</p>
                </div>
                <span>"Policy version "<code>{display_version}</code></span>
            </div>
            <div class="resource-identity">
                <div><span>"Unreferenced grace"</span><strong>{format!("{} seconds", summary.unreferenced_grace_seconds)}</strong></div>
                <div><span>"Sweep interval"</span><strong>{if summary.schedule.is_empty() { "Manual only".to_string() } else { format!("{} seconds", summary.schedule) }}</strong></div>
                <div><span>"Soft byte limit"</span><strong>{summary.soft_max_bytes.map(|value| format!("{value} bytes")).unwrap_or_else(|| "No limit".to_string())}</strong></div>
                <div><span>"Soft object limit"</span><strong>{summary.soft_max_objects.map(|value| value.to_string()).unwrap_or_else(|| "No limit".to_string())}</strong></div>
            </div>
            <details class="advanced-controls"><summary>"Edit garbage-collection policy"</summary>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Unreferenced grace (seconds)"</span><input type="number" min="1" required prop:value=move || grace.get() on:input=move |event| grace.set(event_target_value(&event))/></label>
                <label><span>"Soft maximum bytes (optional)"</span><input type="number" min="1" prop:value=move || max_bytes.get() on:input=move |event| max_bytes.set(event_target_value(&event))/></label>
                <label><span>"Soft maximum objects (optional)"</span><input type="number" min="1" prop:value=move || max_objects.get() on:input=move |event| max_objects.set(event_target_value(&event))/></label>
                <label><span>"Sweep interval (seconds)"</span><input type="number" min="1" prop:value=move || schedule.get() on:input=move |event| schedule.set(event_target_value(&event))/><small>"Leave empty to run sweeps manually."</small></label>
                <label><span>"Deletion concurrency"</span><input type="number" min="1" required prop:value=move || concurrency.get() on:input=move |event| concurrency.set(event_target_value(&event))/></label>
                <label><span>"Initial retry delay (seconds)"</span><input type="number" min="1" required prop:value=move || retry_initial.get() on:input=move |event| retry_initial.set(event_target_value(&event))/></label>
                <label><span>"Maximum retry delay (seconds)"</span><input type="number" min="1" required prop:value=move || retry_max.get() on:input=move |event| retry_max.set(event_target_value(&event))/></label>
                <label><span>"Maximum retry attempts"</span><input type="number" min="1" required prop:value=move || retry_attempts.get() on:input=move |event| retry_attempts.set(event_target_value(&event))/></label>
                <label><span>"Tombstone retention (seconds)"</span><input type="number" min="1" required prop:value=move || tombstone_retention.get() on:input=move |event| tombstone_retention.set(event_target_value(&event))/></label>
                <div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review GC policy"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
            </details>
        </section>
    }
}

#[component]
fn GcPlanner(
    client: ApiClient,
    cache_id: String,
    version: String,
    exact_plan: RwSignal<Option<aos_proto_types::CacheGcPlan>>,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let plan_version = version.clone();
    let on_plan = move |_| {
        let key = idempotency_key("cache-gc-run");
        let inspect_cache_id = cache_id.clone();
        let request = aos_proto_types::PlanRunCacheGcRequest {
            cache_id: cache_id.clone(),
            expected_resource_version: plan_version.clone(),
            idempotency_key: key.clone(),
        };
        let client = plan_client.clone();
        error.set(None);
        pending.set(None);
        exact_plan.set(None);
        busy.set(true);
        spawn_local(async move {
            let planned = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_RUN_CACHE_GC_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, key));
            match planned {
                Ok(reviewed) => {
                    let detail = client
                        .call::<_, aos_proto_types::CacheGcPlanResponse>(
                            aos_proto_types::BINARY_CACHE_SERVICE_GET_CACHE_GC_PLAN_PATH,
                            &aos_proto_types::GetCacheGcPlanRequest {
                                cache_id: inspect_cache_id,
                                plan_id: reviewed.plan.plan_id.clone(),
                            },
                        )
                        .await;
                    match detail {
                        Ok(response) => match response.plan {
                            Some(plan) => {
                                exact_plan.set(Some(plan));
                                pending.set(Some(reviewed));
                            }
                            None => error.set(Some("The Hub omitted the exact GC candidate plan".to_string())),
                        },
                        Err(failure) => error.set(Some(format!(
                            "The sweep was not enabled because its exact candidate plan could not be loaded: {failure}"
                        ))),
                    }
                }
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
                .call::<_, aos_proto_types::OperationResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_RUN_CACHE_GC_PATH,
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
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Immutable candidate snapshot"</p>
                    <h2>"Plan a sweep"</h2>
                    <p>"Planning freezes root, object, topology, policy, and placement inventory versions before review."</p>
                </div>
            </div>
            <div class="compact-list-row"><span>"Bound GC resource version"</span><code>{version}</code></div>
            <div class="form-actions"><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Create candidate plan"</button></div>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || exact_plan.get().map(|plan| view! { <GcPlanDetail plan=plan/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn GcRuns(client: ApiClient, cache_id: String) -> impl IntoView {
    let runs = LocalResource::new(move || {
        let client = client.clone();
        let cache_id = cache_id.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListCacheGcRunsResponse, _, _, _>(
                    aos_proto_types::BINARY_CACHE_SERVICE_LIST_CACHE_GC_RUNS_PATH,
                    move |page_token| aos_proto_types::ListCacheGcRunsRequest {
                        cache_id: cache_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.runs, response.next_page_token),
                )
                .await
        }
    });
    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div><p class="section-kicker">"Audit trail"</p><h2>"GC runs"</h2></div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading GC runs…"</p> }>
                {move || Suspend::new(async move {
                    match runs.await.as_ref() {
                        Ok(runs) if runs.is_empty() => view! {
                            <div class="empty-state"><h3>"No GC runs"</h3><p>"Review a candidate plan to inspect what the current policy would delete. The first sweep requires a separate acknowledgement."</p></div>
                        }
                        .into_any(),
                        Ok(runs) => view! {
                            <div class="binding-list">
                                {runs.iter().cloned().map(|run| view! {
                                    <GcRunCard run=run/>
                                }).collect_view()}
                            </div>
                        }
                        .into_any(),
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn GcRunCard(run: aos_proto_types::CacheGcRun) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{run.operation_id}</strong><code>{run.plan_id}</code></div>
                <StatusBadge state=run.state.clone() positive=run.state == "completed"/>
            </div>
            <div class="resource-identity">
                <div><span>"Scanned"</span><strong>{run.scanned_objects}</strong></div>
                <div><span>"Retained"</span><strong>{run.retained_objects}</strong></div>
                <div><span>"Tombstoned"</span><strong>{run.tombstoned_objects}</strong></div>
                <div><span>"Bytes reclaimed"</span><strong>{run.logical_bytes_reclaimed}</strong></div>
            </div>
            {(!run.error.is_empty()).then(|| view! { <InlineError detail=run.error/> })}
        </article>
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_policy(
    grace: &str,
    max_bytes: &str,
    max_objects: &str,
    schedule: &str,
    concurrency: &str,
    retry_initial: &str,
    retry_max: &str,
    retry_attempts: &str,
    tombstone: &str,
) -> Result<aos_proto_types::CacheGcPolicy, String> {
    if !schedule.trim().is_empty() {
        positive_i64(schedule, "Sweep interval")?;
    }
    Ok(aos_proto_types::CacheGcPolicy {
        unreferenced_grace_seconds: positive_i64(grace, "Grace")?,
        soft_max_bytes: optional_u64(max_bytes, "Maximum bytes")?,
        soft_max_objects: optional_u64(max_objects, "Maximum objects")?,
        schedule: schedule.trim().to_string(),
        deletion_concurrency: positive_u32(concurrency, "Deletion concurrency")?,
        retry_initial_seconds: positive_i64(retry_initial, "Initial retry delay")?,
        retry_max_seconds: positive_i64(retry_max, "Maximum retry delay")?,
        retry_max_attempts: positive_u32(retry_attempts, "Retry attempts")?,
        tombstone_retention_seconds: positive_i64(tombstone, "Tombstone retention")?,
        policy_version: 0,
        resource_version: String::new(),
    })
}
fn positive_i64(value: &str, label: &str) -> Result<i64, String> {
    value
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label} must be a positive integer"))
}
fn positive_u32(value: &str, label: &str) -> Result<u32, String> {
    value
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label} must be a positive integer"))
}
fn optional_u64(value: &str, label: &str) -> Result<Option<u64>, String> {
    if value.trim().is_empty() {
        Ok(None)
    } else {
        value
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .map(Some)
            .ok_or_else(|| format!("{label} must be a positive integer"))
    }
}
fn reload() {
    crate::app::refresh();
}
