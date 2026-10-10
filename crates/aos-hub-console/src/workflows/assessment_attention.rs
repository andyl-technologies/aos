//! Resource-owned alert controls and authorized event replay in the console.

use aos_assessment_runtime::alerts::{AssessmentAlertV1, AttentionState};
use aos_assessment_runtime::attention_control::{
    AlertAcknowledgementV1, AlertPageV1, AlertQueryV1, EventPageV1, EventQueryV1,
};
use aos_assessment_runtime::events::AssessmentEventPayload;
use leptos::prelude::*;

use super::assessments::{AssessmentReadGuard, start_status_poll};
use crate::components::InlineError;
use crate::mutation::{idempotency_key, scoped_workflow_tasks};
use crate::transport::ApiClient;

fn event_description(payload: &AssessmentEventPayload) -> String {
    match payload {
        AssessmentEventPayload::Alert { transition, alert } => {
            format!("{transition:?} alert {}", alert.issue_key)
        }
        AssessmentEventPayload::Acknowledged { alert } => {
            format!("Acknowledged alert {}", alert.issue_key)
        }
        AssessmentEventPayload::ScanCompleted { scan_id, .. } => {
            format!("Scan {scan_id} completed")
        }
        AssessmentEventPayload::ScheduleChanged {
            schedule_id,
            revision,
            enabled,
        } => {
            format!(
                "Schedule {schedule_id} {} at revision {revision}",
                if *enabled { "enabled" } else { "disabled" }
            )
        }
        AssessmentEventPayload::SubscriptionChanged {
            subscription_id,
            revision,
            enabled,
        } => {
            format!(
                "Subscription {subscription_id} {} at revision {revision}",
                if *enabled { "enabled" } else { "disabled" }
            )
        }
        AssessmentEventPayload::DeliveryFailed { failure } => {
            let retry = failure
                .retry_at
                .as_ref()
                .map(|time| format!("; retry eligible at {time}"))
                .unwrap_or_else(|| "; moved to dead letters".into());
            format!(
                "Delivery {} for subscription {} failed on attempt {}{retry}",
                failure.delivery_id, failure.subscription_id, failure.attempt
            )
        }
        AssessmentEventPayload::SourceFailed { failure } => {
            let reason = match failure.code {
                aos_assessment_runtime::events::SourceFailureCode::ExecutionFailed => {
                    "execution incomplete"
                }
                aos_assessment_runtime::events::SourceFailureCode::RateLimited => "rate limited",
                aos_assessment_runtime::events::SourceFailureCode::RetryableResponse => {
                    "retryable response"
                }
                aos_assessment_runtime::events::SourceFailureCode::SourceUnavailable => {
                    "source unavailable"
                }
            };
            let retry = failure
                .retry_at
                .as_ref()
                .map(|time| format!("; source retry boundary {time}"))
                .unwrap_or_default();
            format!(
                "Source {} failed during scan {} on attempt {}: {reason}{retry}",
                failure.provider, failure.scan_id, failure.attempt
            )
        }
    }
}

/// Renders attention history, scoped replay and exact-episode acknowledgement.
#[component]
pub(super) fn RegistryAssessmentAttention(client: ApiClient, slug: String) -> impl IntoView {
    let can_acknowledge = client.allows("assessment.alert.acknowledge");
    let context = StoredValue::new((client, slug));
    let tasks = scoped_workflow_tasks();
    let epoch = RwSignal::new(0_u64);
    let polling = RwSignal::new(true);
    let active_reads = RwSignal::new(0_u32);
    let position = RwSignal::new(None);
    let resource_scope = RwSignal::new(None::<String>);
    let after_sequence = RwSignal::new(0_u64);
    let recent_events =
        RwSignal::new(Vec::<aos_assessment_runtime::events::AssessmentEventV1>::new());
    let selected = RwSignal::new(None::<AssessmentAlertV1>);
    let reason = RwSignal::new(String::new());
    let request_key = RwSignal::new(idempotency_key("assessment-acknowledgement"));
    let busy = RwSignal::new(false);
    let failure = RwSignal::new(None::<String>);

    let page = LocalResource::new(move || {
        let _ = epoch.get();
        let after_issue = position.get();
        let scope = resource_scope.get_untracked();
        let sequence = after_sequence.get_untracked();
        let (client, registry_slug) = context.get_value();
        let read = AssessmentReadGuard::new(active_reads);
        async move {
            let _read = read;
            let outcome = async {
                let query = AlertQueryV1 {
                    schema: "aos.assessment-alert-query/v1".into(),
                    limit: 10,
                    after_issue,
                    resource_scope: scope.clone(),
                };
                let response = client
                    .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_LIST_ALERTS_PATH,
                        &aos_proto_types::AssessmentControlRequest {
                            registry_slug: registry_slug.clone(),
                            document_json: serde_json::to_vec(&query)
                                .map_err(|error| error.to_string())?,
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let alerts = AlertPageV1::from_slice(&response.document_json)
                    .map_err(|error| error.to_string())?;
                if scope
                    .as_ref()
                    .is_some_and(|scope| scope != &alerts.resource_scope)
                {
                    return Err("Assessment resource changed; reopen the registry".to_owned());
                }
                let query = EventQueryV1 {
                    schema: "aos.assessment-event-query/v1".into(),
                    limit: 10,
                    after_sequence: sequence,
                    resource_scope: Some(alerts.resource_scope.clone()),
                };
                let response = client
                    .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_LIST_EVENTS_PATH,
                        &aos_proto_types::AssessmentControlRequest {
                            registry_slug,
                            document_json: serde_json::to_vec(&query)
                                .map_err(|error| error.to_string())?,
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let events = EventPageV1::from_slice(&response.document_json)
                    .map_err(|error| error.to_string())?;
                if events.resource_scope != alerts.resource_scope
                    || events.next_sequence < sequence
                    || events
                        .events
                        .first()
                        .is_some_and(|event| event.sequence <= sequence)
                {
                    return Err("Assessment event replay changed resource or regressed".to_owned());
                }
                resource_scope.set(Some(alerts.resource_scope.clone()));
                after_sequence.set(events.next_sequence);
                recent_events.update(|recent| {
                    recent.extend(events.events);
                    if recent.len() > 50 {
                        recent.drain(..recent.len() - 50);
                    }
                });
                Ok::<_, String>(alerts)
            }
            .await;
            if outcome.is_err() {
                polling.set(false);
            }
            outcome
        }
    });
    start_status_poll(epoch, polling, active_reads);

    let acknowledge = move |_| {
        if busy.get_untracked() || !can_acknowledge || !polling.get_untracked() {
            return;
        }
        let Some(alert) = selected.get_untracked() else {
            return;
        };
        let Some(scope) = resource_scope.get_untracked() else {
            return;
        };
        let note = reason.get_untracked();
        let request = AlertAcknowledgementV1 {
            schema: "aos.assessment-alert-acknowledgement/v1".into(),
            resource_scope: scope.clone(),
            issue_key: alert.issue_key,
            episode: alert.episode,
            expected_sequence: alert.sequence,
            idempotency_key: request_key.get_untracked(),
            reason: (!note.trim().is_empty()).then_some(note),
        };
        let document_json = match serde_json::to_vec(&request) {
            Ok(bytes) => bytes,
            Err(error) => {
                failure.set(Some(error.to_string()));
                return;
            }
        };
        if let Err(error) = AlertAcknowledgementV1::from_slice(&document_json) {
            failure.set(Some(error.to_string()));
            return;
        }
        let (client, registry_slug) = context.get_value();
        busy.set(true);
        failure.set(None);
        tasks.spawn(async move {
            let outcome = async {
                let response = client
                    .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_ACKNOWLEDGE_ALERT_PATH,
                        &aos_proto_types::AssessmentControlRequest {
                            registry_slug,
                            document_json,
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let mut page = AlertPageV1::from_slice(&response.document_json)
                    .map_err(|error| error.to_string())?;
                if page.resource_scope != scope
                    || page.alerts.len() != 1
                    || page.alerts[0].issue_key != alert.issue_key
                    || !page.alerts[0].acknowledgements.iter().any(|ack| {
                        ack.episode == alert.episode
                            && ack.idempotency_key.as_ref() == Some(&request.idempotency_key)
                    })
                {
                    return Err(
                        "Acknowledgement receipt differs from the requested episode".to_owned()
                    );
                }
                selected.set(page.alerts.pop());
                request_key.set(idempotency_key("assessment-acknowledgement"));
                epoch.update(|value| *value = value.wrapping_add(1));
                Ok::<_, String>(())
            }
            .await;
            if let Err(error) = outcome {
                failure.set(Some(error));
            }
            busy.set(false);
        });
    };

    view! {
        <section class="assessment-attention">
            <h3>"Package alerts"</h3>
            <p>"Acknowledgement records attention to one episode. Resolution follows verified package evidence."</p>
            <button class="secondary-button" disabled=move || busy.get() on:click=move |_| {
                polling.set(true); position.set(None);
                epoch.update(|value| *value = value.wrapping_add(1));
            }>"Refresh alerts"</button>
            <Suspense fallback=move || view! { <p>"Loading package alerts…"</p> }>
                {move || Suspend::new(async move {
                    match page.await.as_ref() {
                        Err(error) => view! { <InlineError detail=error.clone()/> }.into_any(),
                        Ok(page) => {
                            let rows = page.alerts.iter().map(|alert| {
                                let alert = alert.clone();
                                let inspected = alert.clone();
                                let acknowledged = alert.acknowledgements.iter().any(|ack| ack.episode == alert.episode);
                                view! { <tr><td>{format!("{:?}", alert.issue.family)}</td><td>{format!("{:?}", alert.state)}</td>
                                    <td>{alert.episode}</td><td>{if alert.issue.uncertain { "Uncertain evidence" } else { "Supported by current evidence" }}</td>
                                    <td>{if acknowledged { "Acknowledged" } else { "Unacknowledged" }}</td>
                                    <td><button disabled=move || busy.get() on:click=move |_| {
                                        selected.set(Some(inspected.clone())); reason.set(String::new());
                                        request_key.set(idempotency_key("assessment-acknowledgement")); failure.set(None);
                                    }>"Inspect episode"</button></td></tr> }
                            }).collect_view();
                            let next = page.next_issue;
                            view! { <p>{format!("Observed at {}", page.as_of)}</p>
                                <table><thead><tr><th>"Issue"</th><th>"State"</th><th>"Episode"</th><th>"Evidence"</th><th>"Attention"</th><th>"Details"</th></tr></thead><tbody>{rows}</tbody></table>
                                {next.map(|next| view! { <button disabled=move || busy.get() on:click=move |_| position.set(Some(next))>"Next alerts"</button> })}
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
            // Keep the selected mutation and retry identity mounted across polls.
            {move || selected.get().map(|alert| view! {
                <article><h4>{format!("Issue {}", alert.issue_key)}</h4>
                    <p>{format!("Episode {}; revision {}; {:?}", alert.episode, alert.sequence, alert.state)}</p>
                    <ul>{alert.acknowledgements.iter().map(|ack| view! { <li>{format!("Episode {}: {} at {}", ack.episode, ack.actor_ref, ack.acknowledged_at)}</li> }).collect_view()}</ul>
                    {(can_acknowledge && alert.state == AttentionState::Open).then(|| view! {
                        <label>"Attention note"<textarea maxlength="4096" disabled=move || busy.get() prop:value=move || reason.get()
                            on:input=move |event| { reason.set(event_target_value(&event)); request_key.set(idempotency_key("assessment-acknowledgement")); }/></label>
                        <button disabled=move || busy.get() || !polling.get() on:click=acknowledge>"Acknowledge this episode"</button>
                    })}
                </article>
            })}
            {move || failure.get().map(|detail| view! { <InlineError detail/> })}
            <h3>"Recent committed events"</h3>
            <p>"Event replay resumes from the last committed sequence and checks access on every poll."</p>
            <ul>{move || recent_events.get().iter().map(|event| view! {
                <li>{format!("{} · {} · {}", event.sequence, event.occurred_at, event_description(&event.payload))}</li>
            }).collect_view()}</ul>
        </section>
    }
}
