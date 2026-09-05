//! Cache GC physical-deletion job recovery workflows.
//!
//! Logical tombstoning and physical placement deletion are separate. Failed
//! physical jobs remain auditable and require reviewed retry or abandonment.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HashValue, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

/// Renders deletion-job lookup and reviewed recovery controls.
#[component]
pub(super) fn GcDeletionJobs(client: ApiClient, cache_id: String) -> impl IntoView {
    let operation_id = RwSignal::new(String::new());
    let jobs = RwSignal::new(None::<Vec<aos_proto_types::CacheGcDeletionJob>>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let list_client = client.clone();
    let list_cache = cache_id.clone();
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let client = list_client.clone();
        let cache_id = list_cache.clone();
        let operation_id = operation_id.get_untracked().trim().to_string();
        error.set(None);
        jobs.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .collect_pages::<_, aos_proto_types::ListCacheGcDeletionJobsResponse, _, _, _>(
                    aos_proto_types::BINARY_CACHE_SERVICE_LIST_CACHE_GC_DELETION_JOBS_PATH,
                    move |page_token| aos_proto_types::ListCacheGcDeletionJobsRequest {
                        cache_id: cache_id.clone(),
                        operation_id: operation_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.jobs, response.next_page_token),
                )
                .await
            {
                Ok(response) => jobs.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    let view_client = client;
    let view_cache = cache_id;

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Physical deletion recovery"</p>
                    <h2>"Deletion jobs"</h2>
                    <p>"Retry transient placement failures or explicitly abandon a permanently failed physical deletion while preserving its audit record."</p>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label>
                    <span>"GC operation ID (optional)"</span>
                    <input prop:value=move || operation_id.get() on:input=move |event| operation_id.set(event_target_value(&event))/>
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Load deletion jobs"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || jobs.get().map(|jobs| {
                if jobs.is_empty() {
                    view! { <div class="empty-state"><h3>"No matching deletion jobs"</h3><p>"Deletion jobs appear after a reviewed sweep starts and remain here until the bound placements finish or report an error."</p></div> }.into_any()
                } else {
                    view! {
                        <div class="binding-list">
                            {jobs.into_iter().map(|job| view! {
                                <DeletionJobCard client=view_client.clone() cache_id=view_cache.clone() job=job/>
                            }).collect_view()}
                        </div>
                    }
                    .into_any()
                }
            })}
        </section>
    }
}

#[component]
fn DeletionJobCard(
    client: ApiClient,
    cache_id: String,
    job: aos_proto_types::CacheGcDeletionJob,
) -> impl IntoView {
    let job_id = job.job_id.clone();
    let version = job.resource_version.clone();
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{job.job_id}</strong><HashValue value=job.store_hash/></div>
                <StatusBadge state=job.state.clone() positive=job.state == "completed"/>
            </div>
            <div class="resource-identity">
                <div><span>"Operation"</span><code>{job.operation_id}</code></div>
                <div><span>"Placement"</span><code>{job.placement_id}</code></div>
                <div><span>"Attempts"</span><strong>{job.attempts}</strong></div>
                <div><span>"Next attempt"</span><strong>{job.next_attempt_at}</strong></div>
                <div><span>"Resource version"</span><code>{job.resource_version}</code></div>
            </div>
            {(!job.last_error.is_empty()).then(|| view! { <InlineError detail=job.last_error/> })}
            <div class="form-actions">
                <JobAction client=client.clone() cache_id=cache_id.clone() job_id=job_id.clone() version=version.clone() action=JobActionKind::Retry/>
                <JobAction client=client cache_id=cache_id job_id=job_id version=version action=JobActionKind::Abandon/>
            </div>
        </article>
    }
}

#[derive(Clone, Copy)]
enum JobActionKind {
    Retry,
    Abandon,
}

#[component]
fn JobAction(
    client: ApiClient,
    cache_id: String,
    job_id: String,
    version: String,
    action: JobActionKind,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |_| {
        let key = idempotency_key(match action {
            JobActionKind::Retry => "gc-job-retry",
            JobActionKind::Abandon => "gc-job-abandon",
        });
        let client = plan_client.clone();
        let cache_id = cache_id.clone();
        let job_id = job_id.clone();
        let version = version.clone();
        error.set(None);
        pending.set(None);
        busy.set(true);
        spawn_local(async move {
            let response = match action {
                JobActionKind::Retry => client.call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_RETRY_CACHE_GC_DELETION_JOB_PATH,
                    &aos_proto_types::PlanRetryCacheGcDeletionJobRequest { cache_id, job_id, expected_resource_version: version, idempotency_key: key.clone() },
                ).await,
                JobActionKind::Abandon => client.call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_ABANDON_CACHE_GC_DELETION_JOB_PATH,
                    &aos_proto_types::PlanAbandonCacheGcDeletionJobRequest { cache_id, job_id, expected_resource_version: version, idempotency_key: key.clone() },
                ).await,
            };
            let result = response
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
            let result = match action {
                JobActionKind::Retry => client
                    .call::<_, aos_proto_types::OperationResponse>(
                        aos_proto_types::BINARY_CACHE_SERVICE_RETRY_CACHE_GC_DELETION_JOB_PATH,
                        &reviewed.topology_apply(),
                    )
                    .await
                    .map(|_| ()),
                JobActionKind::Abandon => client
                    .call::<_, aos_proto_types::CacheGcDeletionJobResponse>(
                        aos_proto_types::BINARY_CACHE_SERVICE_ABANDON_CACHE_GC_DELETION_JOB_PATH,
                        &reviewed.cache_plan_apply(),
                    )
                    .await
                    .map(|_| ()),
            };
            match result {
                Ok(()) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    let label = match action {
        JobActionKind::Retry => "Review retry",
        JobActionKind::Abandon => "Review abandonment",
    };
    view! {
        <div class="subworkflow">
            <button class=if matches!(action, JobActionKind::Abandon) { "danger-button" } else { "table-action" } type="button" disabled=move || busy.get() on:click=on_plan>{label}</button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </div>
    }
}

fn reload() {
    crate::app::refresh();
}
