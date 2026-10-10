//! Read-only notification delivery inspection with finite pages and visibility-aware polling.

use aos_assessment_runtime::notifications::{
    NotificationDeliveryPageV1, NotificationDeliveryQueryV1, NotificationFailureCode,
    NotificationIntentState,
};
use leptos::prelude::*;

use super::assessments::{start_status_poll, AssessmentReadGuard};
use crate::components::InlineError;
use crate::transport::ApiClient;

/// Shows bounded delivery state without offering an authority-bypassing retry operation.
#[component]
pub(super) fn RegistryAssessmentDeliveries(client: ApiClient, slug: String) -> impl IntoView {
    let context = StoredValue::new((client, slug));
    let epoch = RwSignal::new(0_u64);
    let polling = RwSignal::new(true);
    let active = RwSignal::new(0_u32);
    let scope = RwSignal::new(None::<String>);
    let after = RwSignal::new(None::<String>);
    let subscription = RwSignal::new(String::new());
    let selected_subscription = RwSignal::new(None::<String>);
    let delivery = RwSignal::new(None::<String>);
    let page = LocalResource::new(move || {
        let _ = epoch.get();
        let query = NotificationDeliveryQueryV1 {
            schema: "aos.assessment-notification-delivery-query/v1".into(),
            resource_scope: scope.get_untracked(),
            delivery_id: delivery.get(),
            subscription_id: selected_subscription.get(),
            after_delivery: after.get(),
            limit: 10,
        };
        let (client, registry_slug) = context.get_value();
        let read = AssessmentReadGuard::new(active);
        async move {
            let _read = read;
            let outcome = async {
                let response = client
                    .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_LIST_NOTIFICATION_DELIVERIES_PATH,
                        &aos_proto_types::AssessmentControlRequest {
                            registry_slug,
                            document_json: serde_json::to_vec(&query)
                                .map_err(|error| error.to_string())?,
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let page = NotificationDeliveryPageV1::from_slice(&response.document_json)
                    .map_err(|error| error.to_string())?;
                if query
                    .resource_scope
                    .as_ref()
                    .is_some_and(|scope| scope != &page.resource_scope)
                    || page.subscription_id != query.subscription_id
                    || page.deliveries.len() > query.limit as usize
                    || query.delivery_id.as_ref().is_some_and(|identity| {
                        page.deliveries.len() != 1 || page.deliveries[0].delivery_id != *identity
                    })
                {
                    return Err(
                        "The delivery selection changed. Refresh before continuing.".to_owned()
                    );
                }
                scope.set(Some(page.resource_scope.clone()));
                if page.next_delivery.is_some() || query.after_delivery.is_some() {
                    polling.set(false);
                }
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

    view! {
        <div class="assessment-deliveries">
            <h4>"Notification deliveries"</h4>
            <p>"Delivered records confirm an accepted destination response. An expired lease may have an uncertain physical outcome; read operations do not retry it."</p>
            <label>"Subscription filter"<input prop:value=move || subscription.get() on:input=move |event| subscription.set(event_target_value(&event))/></label>
            <button class="secondary-button" on:click=move |_| {
                let value = subscription.get_untracked().trim().to_owned();
                selected_subscription.set((!value.is_empty()).then_some(value));
                delivery.set(None); after.set(None); scope.set(None); polling.set(true);
                epoch.update(|epoch| *epoch = epoch.wrapping_add(1));
            }>"Refresh deliveries"</button>
            {move || delivery.get().map(|_| view! {
                <button class="secondary-button" on:click=move |_| { delivery.set(None); after.set(None); polling.set(true); }>"Back to delivery list"</button>
            })}
            <Suspense fallback=move || view! { <p>"Loading deliveries…"</p> }>
                {move || Suspend::new(async move { match page.await.as_ref() {
                    Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    Ok(page) => {
                        let rows = page.deliveries.iter().cloned().map(|item| {
                            let id = item.delivery_id.clone();
                            let state = match item.state {
                                NotificationIntentState::Pending => "Pending",
                                NotificationIntentState::Leased => "Leased",
                                NotificationIntentState::Delivered => "Delivered",
                                NotificationIntentState::DeadLetter => "Dead letter",
                                NotificationIntentState::Revoked => "Revoked",
                            };
                            let failure = item.last_error_code.map(|reason| match reason {
                                NotificationFailureCode::SubscriptionReviewReplaced => "Review replaced",
                                NotificationFailureCode::NotificationReviewExpired => "Review expired",
                                NotificationFailureCode::NotificationAttemptOrAgeExhausted => "Attempt or age limit reached",
                                NotificationFailureCode::DestinationRetryable => "Retryable outcome",
                                NotificationFailureCode::DestinationPermanentFailure => "Permanent destination failure",
                            }).unwrap_or("");
                            view! { <tr>
                                <td><button class="secondary-button" on:click=move |_| { after.set(None); delivery.set(Some(id.clone())); polling.set(true); }>{item.delivery_id}</button></td>
                                <td>{item.subscription_id}</td><td>{item.event_sequence}</td>
                                <td>{state}</td><td>{item.attempt}</td><td>{item.not_before.to_string()}</td>
                                <td>{item.lease_expires_at.map(|time| time.to_string()).unwrap_or_default()}</td>
                                <td>{failure}</td><td>{item.batch_delivery_id.unwrap_or_default()}</td>
                            </tr> }
                        }).collect_view();
                        view! {
                            <p>{format!("Status observed at {}", page.as_of)}</p>
                            <table><thead><tr>
                                <th>"Delivery"</th><th>"Subscription"</th><th>"Event"</th>
                                <th>"State"</th><th>"Attempts"</th><th>"Eligible at"</th>
                                <th>"Lease expires"</th><th>"Failure"</th><th>"Physical batch"</th>
                            </tr></thead><tbody>{rows}</tbody></table>
                            {page.next_delivery.clone().map(|identity| view! {
                                <button class="secondary-button" on:click=move |_| after.set(Some(identity.clone()))>"Next deliveries"</button>
                            })}
                        }.into_any()
                    }
                } })}
            </Suspense>
        </div>
    }
}
