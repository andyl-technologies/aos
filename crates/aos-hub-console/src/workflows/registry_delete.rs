//! Registry Danger-zone deletion with a readiness review and live progress.
//!
//! The review shows the plan's effects next to the Hub's exact deletion
//! readiness: what blocks deletion and must be resolved by an operator, or
//! which steps the deletion operation performs itself. Applying starts that
//! operation; the page then follows it until the registry is deleted or the
//! operation fails with its recorded blocker breakdown.

use std::time::Duration;

use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::app::navigate;
use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, spawn_workflow_task as spawn_local, PendingPlan};
use crate::registry_deletion::{
    blocker_rows, deletion_progress, placement_state_label, verdict_label, DeletionProgress,
};
use crate::transport::ApiClient;

/// Delay between operation reads while a deletion runs.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Reviews and applies deletion of one registry.
#[component]
pub(super) fn RegistryDelete(
    client: ApiClient,
    stable_id: String,
    resource_version: String,
    return_path: String,
) -> impl IntoView {
    let confirmation = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let readiness = RwSignal::new(None::<aos_proto_types::RegistryDeletionReadiness>);
    let progress = RwSignal::new(None::<(aos_proto_types::OperationDetail, DeletionProgress)>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let confirmation_target = stable_id.clone();

    let plan_client = client.clone();
    let required = stable_id.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        if confirmation.get_untracked() != required {
            error.set(Some("Type the exact registry stable ID to continue".to_string()));
            return;
        }
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("registry-delete");
        let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
            stable_id: required.clone(),
            expected_resource_version: Some(resource_version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        progress.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::RegistryDeletePlanResponse>(
                    aos_proto_types::REGISTRY_SERVICE_PLAN_DELETE_REGISTRY_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string());
            match result {
                Ok(response) => {
                    readiness.set(response.readiness);
                    let plan = aos_proto_types::TopologyPlanResponse {
                        plan: response.plan,
                    };
                    match PendingPlan::from_response(plan, idempotency_key) {
                        Ok(reviewed) => pending.set(Some(reviewed)),
                        Err(detail) => error.set(Some(detail)),
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
        let return_path = return_path.clone();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let started = client
                .call::<_, aos_proto_types::OperationResponse>(
                    aos_proto_types::REGISTRY_SERVICE_DELETE_REGISTRY_PATH,
                    &reviewed.delete_apply(),
                )
                .await;
            let operation_id = match started {
                Ok(response) => response
                    .operation
                    .map(|operation| operation.operation_id)
                    .unwrap_or_default(),
                Err(failure) => {
                    error.set(Some(failure.to_string()));
                    busy.set(false);
                    return;
                }
            };
            pending.set(None);
            follow_deletion(client, operation_id, progress, error, return_path).await;
            busy.set(false);
        });
    });

    view! {
        <section class="panel danger-panel">
            <p class="section-kicker">"Destructive operation"</p>
            <h2>"Delete registry"</h2>
            <p>"The review lists exactly what blocks deletion, or the steps the deletion operation performs itself: abandoning never-applied GC plans, fencing registry writes, and collecting a fresh provider inventory of every placement. An empty registry is deleted by one apply."</p>
            <form class="editor-form" on:submit=on_plan>
                <label class="full-field">
                    <span>"Type "<code>{stable_id}</code>" to continue"</span>
                    <input autocomplete="off" prop:value=move || confirmation.get() on:input=move |event| confirmation.set(event_target_value(&event))/>
                </label>
                <div class="form-actions">
                    <button class="danger-button" type="submit" disabled=move || busy.get() || confirmation.get() != confirmation_target>"Review deletion"</button>
                </div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || progress.get().map(|(operation, detail)| view! { <DeletionProgressPanel operation=operation detail=detail/> })}
            {move || {
                let current = readiness.get();
                pending.get().map(|reviewed| {
                    let blocked = current.as_ref().is_some_and(|readiness| readiness.verdict == "blocked");
                    view! {
                        {current.map(|readiness| view! { <ReadinessPanel readiness=readiness/> })}
                        {if blocked {
                            view! {
                                <div class="form-actions">
                                    <p>"The Hub refuses this deletion until the blocking conditions are resolved."</p>
                                    <button class="secondary-button" type="button" on:click=move |_| pending.set(None)>"Back"</button>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None)) action_label="Delete registry"/>
                            }.into_any()
                        }}
                    }
                })
            }}
        </section>
    }
}

/// Polls the deletion operation until it is terminal.
async fn follow_deletion(
    client: ApiClient,
    operation_id: String,
    progress: RwSignal<Option<(aos_proto_types::OperationDetail, DeletionProgress)>>,
    error: RwSignal<Option<String>>,
    return_path: String,
) {
    loop {
        let read = client
            .call::<_, aos_proto_types::OperationDetailResponse>(
                aos_proto_types::OPERATION_SERVICE_GET_OPERATION_PATH,
                &aos_proto_types::GetOperationRequest {
                    operation_id: operation_id.clone(),
                },
            )
            .await;
        let operation = match read.map(|response| response.operation) {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                error.set(Some("The Hub omitted the deletion operation.".to_string()));
                return;
            }
            Err(failure) => {
                error.set(Some(failure.to_string()));
                return;
            }
        };
        let state = operation
            .operation
            .as_ref()
            .map(|reference| reference.state.clone())
            .unwrap_or_default();
        let detail = deletion_progress(&operation.detail_json);
        let failure = operation.error.clone();
        progress.set(Some((operation, detail)));
        match state.as_str() {
            "succeeded" => {
                navigate(&return_path);
                return;
            }
            "failed" | "cancelled" => {
                error.set(Some(format!("Registry deletion {state}: {failure}")));
                return;
            }
            _ => sleep(POLL_INTERVAL).await,
        }
    }
}

/// Resolves after `duration` on the browser event loop.
async fn sleep(duration: Duration) {
    let (sender, receiver) = futures::channel::oneshot::channel::<()>();
    leptos::leptos_dom::helpers::set_timeout(
        move || {
            let _ = sender.send(());
        },
        duration,
    );
    let _ = receiver.await;
}

/// Shows the phase of a running or finished deletion operation.
#[component]
fn DeletionProgressPanel(
    operation: aos_proto_types::OperationDetail,
    detail: DeletionProgress,
) -> impl IntoView {
    let reference = operation.operation.unwrap_or_default();
    let positive = reference.state == "succeeded";
    view! {
        <section class="panel">
            <div class="review-heading">
                <div>
                    <p class="section-kicker">"Deletion operation"</p>
                    <h2>{format!("Phase: {}", if detail.phase.is_empty() { "pending" } else { detail.phase.as_str() })}</h2>
                </div>
                <StatusBadge state=reference.state.clone() positive=positive/>
            </div>
            <p>{detail.message}</p>
            <code>{reference.operation_id}</code>
            {detail.readiness.map(|readiness| view! { <ReadinessPanel readiness=readiness/> })}
        </section>
    }
}

/// Renders a readiness verdict, its reasons and steps, and exact counts.
#[component]
fn ReadinessPanel(readiness: aos_proto_types::RegistryDeletionReadiness) -> impl IntoView {
    let rows = blocker_rows(&readiness);
    let positive = readiness.verdict != "blocked";
    view! {
        <section class="panel">
            <div class="review-heading">
                <div>
                    <p class="section-kicker">"Deletion readiness"</p>
                    <h2>{verdict_label(&readiness.verdict)}</h2>
                </div>
                <StatusBadge state=readiness.verdict.clone() positive=positive/>
            </div>
            {(!readiness.blocking_reasons.is_empty()).then(|| view! {
                <div class="warning-list">
                    <h3>"What blocks deletion"</h3>
                    <ul>{readiness.blocking_reasons.into_iter().map(|reason| view! { <li>{reason}</li> }).collect_view()}</ul>
                </div>
            })}
            {(!readiness.automatic_steps.is_empty()).then(|| view! {
                <div>
                    <h3>"What the deletion operation does"</h3>
                    <ol>{readiness.automatic_steps.into_iter().map(|step| view! { <li>{step}</li> }).collect_view()}</ol>
                </div>
            })}
            {(!rows.is_empty()).then(|| view! {
                <table class="resource-table">
                    <thead><tr><th>"Condition"</th><th>"Count"</th><th>"Resolution"</th></tr></thead>
                    <tbody>{rows.into_iter().map(|row| view! {
                        <tr><td>{row.label}</td><td>{row.count.to_string()}</td><td>{row.severity.label()}</td></tr>
                    }).collect_view()}</tbody>
                </table>
            })}
            {(!readiness.placements.is_empty()).then(|| view! {
                <table class="resource-table">
                    <thead><tr><th>"Placement"</th><th>"Inventory"</th><th>"Detail"</th></tr></thead>
                    <tbody>{readiness.placements.into_iter().map(|placement| view! {
                        <tr><td><code>{placement.placement_name}</code></td><td>{placement_state_label(&placement.inventory_state)}</td><td>{placement.detail}</td></tr>
                    }).collect_view()}</tbody>
                </table>
            })}
        </section>
    }
}
