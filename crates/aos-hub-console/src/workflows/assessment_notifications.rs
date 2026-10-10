//! Registered-destination notification review and finite subscription inspection.

use aos_assessment::time::Timestamp;
use aos_assessment_runtime::alerts::IssueFamily;
use aos_assessment_runtime::notifications::{
    DestinationReviewQueryV1, NotificationConfigurationV1, NotificationDestinationV1,
    NotificationEventKind, NotificationFrequency, NotificationThreshold, SubscriptionPageV1,
    SubscriptionQueryV1, SubscriptionV1, SubscriptionWriteV1,
};
use leptos::prelude::*;

use super::assessment_deliveries::RegistryAssessmentDeliveries;
use super::assessments::{start_status_poll, AssessmentReadGuard};
use crate::components::InlineError;
use crate::mutation::{idempotency_key, scoped_workflow_tasks, PendingPlan};
use crate::transport::ApiClient;

/// Shows reviewed notifications without exposing private actor or signing material.
#[component]
pub(super) fn RegistryAssessmentNotifications(client: ApiClient, slug: String) -> impl IntoView {
    let can_review =
        client.allows("assessment.subscription.manage") && client.allows("assessment.read");
    let context = StoredValue::new((client, slug));
    let tasks = scoped_workflow_tasks();
    let epoch = RwSignal::new(0_u64);
    let polling = RwSignal::new(true);
    let active = RwSignal::new(0_u32);
    let scope = RwSignal::new(None::<String>);
    let after = RwSignal::new(None::<String>);
    let selected = RwSignal::new(None::<SubscriptionV1>);
    let identity = RwSignal::new(String::new());
    let destination = RwSignal::new(String::new());
    let expiry = RwSignal::new(String::new());
    let digest = RwSignal::new(false);
    let window = RwSignal::new("300".to_owned());
    let uncertainty = RwSignal::new(true);
    let enabled = RwSignal::new(true);
    let busy = RwSignal::new(false);
    let failure = RwSignal::new(None::<String>);
    let pending = RwSignal::new(None::<(PendingPlan, SubscriptionWriteV1)>);

    let page = LocalResource::new(move || {
        let _ = epoch.get();
        let query = SubscriptionQueryV1 {
            schema: "aos.assessment-subscription-query/v1".into(),
            resource_scope: scope.get_untracked(),
            subscription_id: None,
            after_subscription: after.get(),
            limit: 10,
        };
        let (client, registry_slug) = context.get_value();
        let read = AssessmentReadGuard::new(active);
        async move {
            let _read = read;
            let outcome = async {
                let response = client
                    .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_LIST_SUBSCRIPTIONS_PATH,
                        &aos_proto_types::AssessmentControlRequest {
                            registry_slug,
                            document_json: serde_json::to_vec(&query)
                                .map_err(|error| error.to_string())?,
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let page = SubscriptionPageV1::from_slice(&response.document_json)
                    .map_err(|error| error.to_string())?;
                if query
                    .resource_scope
                    .as_ref()
                    .is_some_and(|scope| scope != &page.resource_scope)
                {
                    return Err(
                        "The notification resource changed. Refresh before editing.".to_owned()
                    );
                }
                scope.set(Some(page.resource_scope.clone()));
                Ok::<_, String>(page)
            }
            .await;
            if outcome.is_err() {
                polling.set(false);
            }
            outcome
        }
    });
    start_status_poll(epoch, polling, active);

    let save = move |_| {
        if !can_review || busy.get_untracked() || !polling.get_untracked() {
            return;
        }
        let Some(resource_scope) = scope.get_untracked() else {
            return;
        };
        let existing = selected.get_untracked();
        let subscription_id = identity.get_untracked().trim().to_owned();
        let destination_reference = destination.get_untracked().trim().to_owned();
        let expires = expiry.get_untracked().trim().to_owned();
        let use_digest = digest.get_untracked();
        let seconds = window.get_untracked();
        let include_uncertainty = uncertainty.get_untracked();
        let is_enabled = enabled.get_untracked();
        let (client, registry_slug) = context.get_value();
        busy.set(true);
        failure.set(None);
        tasks.spawn(async move {
            let outcome = async {
                let configuration = if !is_enabled && existing.is_some() {
                    existing
                        .as_ref()
                        .ok_or_else(|| "Select a review to disable".to_owned())?
                        .configuration
                        .clone()
                } else {
                    let review_expires_at = Timestamp::parse(&expires)
                        .map_err(|error| error.to_string())?;
                    let query = DestinationReviewQueryV1 {
                        schema: "aos.assessment-notification-destination-query/v1".into(),
                        resource_scope: resource_scope.clone(),
                        destination_reference: destination_reference.clone(),
                        review_expires_at: review_expires_at.clone(),
                    };
                    let response = client
                        .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                            aos_proto_types::ASSESSMENT_SERVICE_REVIEW_NOTIFICATION_DESTINATION_PATH,
                            &aos_proto_types::AssessmentControlRequest {
                                registry_slug: registry_slug.clone(),
                                document_json: serde_json::to_vec(&query)
                                    .map_err(|error| error.to_string())?,
                            },
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                    let reviewed = NotificationDestinationV1::from_slice(&response.document_json)
                        .map_err(|error| error.to_string())?;
                    reviewed.validate().map_err(|error| error.to_string())?;
                    if reviewed.resource_scope != resource_scope
                        || reviewed.destination_reference != destination_reference
                        || reviewed.expires_at != review_expires_at
                    {
                        return Err("The registered destination review differs from the selection".to_owned());
                    }
                    NotificationConfigurationV1 {
                        schema: "aos.assessment-notification-configuration/v1".into(),
                        events: existing.as_ref().map_or_else(
                            || vec![
                                NotificationEventKind::AlertOpened,
                                NotificationEventKind::AlertChanged,
                                NotificationEventKind::AlertResolved,
                                NotificationEventKind::AlertRetired,
                                NotificationEventKind::AlertAcknowledged,
                                NotificationEventKind::ScanCompleted,
                                NotificationEventKind::ScheduleChanged,
                                NotificationEventKind::SubscriptionChanged,
                            ],
                            |value| value.configuration.events.clone(),
                        ),
                        families: existing.as_ref().map_or_else(
                            || vec![
                                IssueFamily::Vulnerability,
                                IssueFamily::PackageUpdate,
                                IssueFamily::Coverage,
                                IssueFamily::SourceHealth,
                            ],
                            |value| value.configuration.families.clone(),
                        ),
                        threshold: if include_uncertainty {
                            NotificationThreshold::AllAttention
                        } else {
                            NotificationThreshold::ConfirmedAttention
                        },
                        frequency: if use_digest {
                            NotificationFrequency::Digest {
                                window_seconds: seconds.parse().map_err(|_| {
                                    "Enter a whole number of seconds for the digest window".to_owned()
                                })?,
                            }
                        } else {
                            NotificationFrequency::Immediate
                        },
                        destination_reference: reviewed.destination_reference.clone(),
                        destination_revision: reviewed.revision,
                        destination_digest: reviewed.digest().map_err(|error| error.to_string())?,
                        review_expires_at,
                    }
                };
                let request = SubscriptionWriteV1 {
                    schema: "aos.assessment-subscription-write/v1".into(),
                    resource_scope,
                    subscription_id,
                    expected_revision: existing.as_ref().map_or(0, |value| value.revision),
                    enabled: is_enabled,
                    configuration,
                };
                request.validate().map_err(|error| error.to_string())?;
                let key = idempotency_key("assessment-review");
                let response = client
                    .call::<_, aos_proto_types::TopologyPlanResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_PLAN_WRITE_SUBSCRIPTION_PATH,
                        &aos_proto_types::PlanAssessmentReviewRequest {
                            registry_slug,
                            document_json: serde_json::to_vec(&request).map_err(|error| error.to_string())?,
                            expected_resource_version: request.expected_revision.to_string(),
                            idempotency_key: key.clone(),
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let plan = PendingPlan::from_response(response, key)?;
                Ok::<_, String>((plan, request))
            }
            .await;

            busy.set(false);
            match outcome {
                Ok(review) => {
                    if scope.get_untracked().as_ref() == Some(&review.1.resource_scope) {
                        pending.set(Some(review));
                    }
                }
                Err(error) => failure.set(Some(error)),
            }
        });
    };

    let apply = move |_| {
        if busy.get_untracked() || !can_review || !polling.get_untracked() {
            return;
        }
        let Some((plan, request)) = pending.get_untracked() else {
            return;
        };
        if scope.get_untracked().as_ref() != Some(&request.resource_scope) {
            pending.set(None);
            failure.set(Some(
                "The reviewed resource changed. Plan again before applying.".into(),
            ));
            return;
        }
        let (client, _) = context.get_value();
        busy.set(true);
        failure.set(None);
        tasks.spawn(async move {
            let outcome = async {
                let response = client
                    .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_WRITE_SUBSCRIPTION_PATH,
                        &plan.registry_apply(),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let admitted = SubscriptionV1::from_slice(&response.document_json)
                    .map_err(|error| error.to_string())?;
                if admitted.resource_scope != request.resource_scope
                    || admitted.subscription_id != request.subscription_id
                    || admitted.enabled != request.enabled
                    || admitted.configuration != request.configuration
                    || request.expected_revision.checked_add(1) != Some(admitted.revision)
                {
                    return Err(
                        "The receipt differs from the exact reviewed configuration".to_owned()
                    );
                }
                Ok::<_, String>(admitted)
            }
            .await;
            busy.set(false);
            match outcome {
                Ok(admitted) => {
                    if scope.get_untracked().as_ref() == Some(&request.resource_scope) {
                        selected.set(Some(admitted));
                        pending.set(None);
                        epoch.update(|epoch| *epoch = epoch.wrapping_add(1));
                    }
                }
                Err(error) => failure.set(Some(error)),
            }
        });
    };

    view! {
        <section class="assessment-notifications">
            <div class="section-heading">
                <h3>"Notifications"</h3>
                <button class="secondary-button" on:click=move |_| {
                    pending.set(None);
                    selected.set(None);
                    scope.set(None);
                    after.set(None);
                    polling.set(true);
                    epoch.update(|epoch| *epoch = epoch.wrapping_add(1));
                }>
                    "Refresh notifications"
                </button>
            </div>
            <Suspense fallback=move || view! { <p>"Loading notification reviews…"</p> }>
                {move || Suspend::new(async move {
                    match page.await.as_ref() {
                        Err(error) => view! { <InlineError detail=error.clone()/> }.into_any(),
                        Ok(page) => {
                            let now = page.as_of.clone();
                            let rows = page.subscriptions.iter().cloned().map(move |subscription| {
                                let label = subscription.subscription_id.clone();
                                let destination_label = subscription.configuration.destination_reference.clone();
                                let deadline = subscription.authority_expires_at.to_string();
                                let state = if !subscription.enabled {
                                    "Disabled"
                                } else if subscription.authority_expires_at <= now {
                                    "Review expired"
                                } else {
                                    "Enabled"
                                };
                                view! {
                                    <tr>
                                        <td>{label}</td>
                                        <td>{destination_label}</td>
                                        <td>{state}</td>
                                        <td>{deadline}</td>
                                        <td>{can_review.then(|| view! {
                                            <button class="secondary-button"
                                                disabled=move || (busy.get() || pending.get().is_some())
                                                on:click=move |_| {
                                                    identity.set(subscription.subscription_id.clone());
                                                    destination.set(subscription.configuration.destination_reference.clone());
                                                    expiry.set(subscription.configuration.review_expires_at.to_string());
                                                    uncertainty.set(subscription.configuration.threshold == NotificationThreshold::AllAttention);
                                                    match subscription.configuration.frequency {
                                                        NotificationFrequency::Immediate => digest.set(false),
                                                        NotificationFrequency::Digest { window_seconds } => {
                                                            digest.set(true);
                                                            window.set(window_seconds.to_string());
                                                        }
                                                    }
                                                    enabled.set(subscription.enabled);
                                                    selected.set(Some(subscription.clone()));
                                                    failure.set(None);
                                                }
                                            >
                                                "Edit review"
                                            </button>
                                        })}</td>
                                    </tr>
                                }
                            }).collect_view();
                            let next = page.next_subscription.clone();
                            view! {
                                <table>
                                    <thead><tr>
                                        <th>"Subscription"</th>
                                        <th>"Destination"</th>
                                        <th>"State"</th>
                                        <th>"Authority expires"</th>
                                        <th>"Review"</th>
                                    </tr></thead>
                                    <tbody>{rows}</tbody>
                                </table>
                                {next.map(|identity| view! {
                                    <button class="secondary-button"
                                        on:click=move |_| after.set(Some(identity.clone()))
                                    >
                                        "Next notifications"
                                    </button>
                                })}
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
            {can_review.then(|| view! {
                <div class="assessment-notification-form"><h4>"Review notifications"</h4>
                    <p>"New subscriptions receive attention transitions, completed scans and review changes. Editing preserves their selected event kinds and issue families."</p>
                    <label>"Subscription name"<input prop:value=move || identity.get() disabled=move || (busy.get() || pending.get().is_some()) || selected.get().is_some() on:input=move |event| identity.set(event_target_value(&event))/></label>
                    <label>"Registered webhook reference"<input placeholder="webhook:42" prop:value=move || destination.get() disabled=move || (busy.get() || pending.get().is_some()) || (!enabled.get() && selected.get().is_some()) on:input=move |event| destination.set(event_target_value(&event))/></label>
                    <label>"Review expires (UTC)"<input placeholder="2026-10-10T00:00:00Z" prop:value=move || expiry.get() disabled=move || (busy.get() || pending.get().is_some()) || (!enabled.get() && selected.get().is_some()) on:input=move |event| expiry.set(event_target_value(&event))/></label>
                    <label><input type="checkbox" prop:checked=move || digest.get() disabled=move || (busy.get() || pending.get().is_some()) || (!enabled.get() && selected.get().is_some()) on:change=move |event| digest.set(event_target_checked(&event))/>"Group events into digests"</label>
                    <label>"Digest window in seconds"<input type="number" min="60" max="86400" prop:value=move || window.get() disabled=move || (busy.get() || pending.get().is_some()) || !digest.get() || (!enabled.get() && selected.get().is_some()) on:input=move |event| window.set(event_target_value(&event))/></label>
                    <label><input type="checkbox" prop:checked=move || uncertainty.get() disabled=move || (busy.get() || pending.get().is_some()) || (!enabled.get() && selected.get().is_some()) on:change=move |event| uncertainty.set(event_target_checked(&event))/>"Include uncertain attention"</label>
                    <label><input type="checkbox" prop:checked=move || enabled.get() disabled=move || (busy.get() || pending.get().is_some()) on:change=move |event| enabled.set(event_target_checked(&event))/>"Enable notifications"</label>
                    <button class="primary-button" disabled=move || (busy.get() || pending.get().is_some()) || !polling.get() || scope.get().is_none() on:click=save>"Plan notification review"</button>
                    <button class="secondary-button" disabled=move || (busy.get() || pending.get().is_some()) on:click=move |_| { selected.set(None); identity.set(String::new()); enabled.set(true); failure.set(None); }>"New subscription"</button>

                    {move || pending.get().map(|(review, _)| {
                        let effects = review.plan.effects.join("\n");
                        let warnings = review.plan.warnings.join("\n");
                        view! {
                            <div class="assessment-review-confirmation">
                                <h4>"Confirm exact configuration"</h4>
                                <pre>{effects}</pre><p>{warnings}</p>
                                <p>{format!("Plan {} · expires {} · commitment {}", review.plan.plan_id, review.plan.expires_at, review.plan.confirmation_hash)}</p>
                                <button class="primary-button" disabled=move || busy.get() || !polling.get() on:click=apply>"Apply exact reviewed configuration"</button>
                                <button class="secondary-button" disabled=move || busy.get() on:click=move |_| pending.set(None)>"Discard review"</button>
                            </div>
                        }
                    })}
                    {move || failure.get().map(|detail| view! { <InlineError detail=detail/> })}
                </div>
            })}
            <RegistryAssessmentDeliveries client=context.get_value().0 slug=context.get_value().1/>
        </section>
    }
}
