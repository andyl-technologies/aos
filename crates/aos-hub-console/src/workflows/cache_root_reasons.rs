//! Effective cache-retention explanation workflows.
//!
//! Root reasons expose the provenance that makes an object live: registry
//! subscriptions, release identities, manual roots, and leases. This is the
//! operator-facing bridge between retention configuration and safe GC.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HashValue, InlineError, StatusBadge};
use crate::transport::ApiClient;

/// Renders filters and provenance for effective retention roots.
#[component]
pub(super) fn RetentionReasons(client: ApiClient, cache_id: String) -> impl IntoView {
    let registry_id = RwSignal::new(String::new());
    let store_hash = RwSignal::new(String::new());
    let reasons = RwSignal::new(None::<Vec<aos_proto_types::RootReason>>);
    let explanation = RwSignal::new(None::<aos_proto_types::ExplainRetentionResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let client = client.clone();
        let cache_id = cache_id.clone();
        let registry_id = registry_id.get_untracked().trim().to_string();
        let store_hash = store_hash.get_untracked().trim().to_string();
        error.set(None);
        reasons.set(None);
        explanation.set(None);
        busy.set(true);
        spawn_local(async move {
            let list_cache_id = cache_id.clone();
            let list_registry_id = registry_id.clone();
            let list_store_hash = store_hash.clone();
            let listed = client
                .collect_pages::<_, aos_proto_types::ListRootReasonsResponse, _, _, _>(
                    aos_proto_types::BINARY_CACHE_SERVICE_LIST_ROOT_REASONS_PATH,
                    move |page_token| aos_proto_types::ListRootReasonsRequest {
                        cache_id: list_cache_id.clone(),
                        registry_id: list_registry_id.clone(),
                        store_hash: list_store_hash.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.reasons, response.next_page_token),
                )
                .await;
            match listed {
                Ok(response) => reasons.set(Some(response)),
                Err(failure) => {
                    error.set(Some(failure.to_string()));
                    busy.set(false);
                    return;
                }
            }
            if !store_hash.is_empty() {
                match client
                    .call::<_, aos_proto_types::ExplainRetentionResponse>(
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_EXPLAIN_RETENTION_PATH,
                        &aos_proto_types::ExplainRetentionRequest {
                            cache_id,
                            store_hash,
                        },
                    )
                    .await
                {
                    Ok(response) => explanation.set(Some(response)),
                    Err(failure) => error.set(Some(failure.to_string())),
                }
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"GC provenance"</p>
                    <h2>"Explain effective roots"</h2>
                    <p>
                        "Inspect every reason an object remains live before changing retention or running garbage collection."
                    </p>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label>
                    <span>"Registry stable ID (optional)"</span>
                    <input prop:value=move || registry_id.get() on:input=move |event| registry_id.set(event_target_value(&event))/>
                </label>
                <label>
                    <span>"Store hash (optional)"</span>
                    <input prop:value=move || store_hash.get() on:input=move |event| store_hash.set(event_target_value(&event))/>
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    {move || if busy.get() { "Inspecting…" } else { "Inspect root reasons" }}
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || explanation.get().map(|response| view! {
                <div class="compact-list-row">
                    <strong>"Selected object"</strong>
                    <StatusBadge
                        state=if response.retained { "retained" } else { "collectible" }.to_string()
                        positive=response.retained
                    />
                </div>
            })}
            {move || reasons.get().map(|reasons| {
                if reasons.is_empty() {
                    view! { <p class="muted">"No matching retention roots."</p> }.into_any()
                } else {
                    view! {
                        <div class="binding-list">
                            {reasons.into_iter().map(|reason| view! {
                                <RootReasonCard reason=reason/>
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
fn RootReasonCard(reason: aos_proto_types::RootReason) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><HashValue value=reason.store_hash/><code>{reason.reason_id}</code></div>
                <StatusBadge state=reason.source_kind positive=true/>
            </div>
            <div class="resource-identity">
                <div><span>"Registry"</span><code>{display_or(&reason.registry_id, "none")}</code></div>
                <div><span>"Release"</span><code>{display_or(&reason.release_id, "none")}</code></div>
                <div><span>"Subscription"</span><code>{display_or(&reason.retention_subscription_id, "none")}</code></div>
                <div><span>"Manual root"</span><code>{display_or(&reason.manual_retention_root_id, "none")}</code></div>
                <div><span>"Lease"</span><code>{display_or(&reason.retention_lease_id, "none")}</code></div>
                <div><span>"Reason key"</span><code>{reason.reason_key}</code></div>
            </div>
        </article>
    }
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}
