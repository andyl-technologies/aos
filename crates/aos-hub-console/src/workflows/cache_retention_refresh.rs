//! Cache-wide retention refresh workflow.
//!
//! Refresh-all resolves every registry subscription against current signed
//! catalogs under the same cache-wide GC concurrency fence used by sweeps.

use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

/// Renders a reviewed refresh of every registry retention subscription.
#[component]
pub(super) fn RefreshAllRetention(client: ApiClient, cache_id: String) -> impl IntoView {
    let state_client = client.clone();
    let state_cache = cache_id.clone();
    let state = LocalResource::new(move || {
        let client = state_client.clone();
        let cache_id = state_cache.clone();
        async move {
            client
                .call::<_, aos_proto_types::GetCacheGcPolicyResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_CACHE_GC_POLICY_PATH,
                    &aos_proto_types::GetCacheGcPolicyRequest { cache_id },
                )
                .await
        }
    });
    let view_client = client;
    let view_cache = cache_id;

    view! {
        <Suspense fallback=move || view! { <section class="panel"><p class="loading-row">"Loading retention fence…"</p></section> }>
            {move || {
                let client = view_client.clone();
                let cache_id = view_cache.clone();
                Suspend::new(async move {
                    match state.await.as_ref() {
                        Ok(response) => {
                            let version = response.generation.as_ref().map(|value| value.resource_version.clone()).unwrap_or_default();
                            view! { <RefreshAllEditor client=client cache_id=cache_id version=version/> }.into_any()
                        }
                        Err(failure) => view! { <section class="panel"><InlineError detail=failure.to_string()/></section> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn RefreshAllEditor(client: ApiClient, cache_id: String, version: String) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let plan_version = version.clone();
    let on_plan = move |_| {
        if plan_version.is_empty() {
            error.set(Some(
                "The Hub omitted the cache retention fence".to_string(),
            ));
            return;
        }
        let key = idempotency_key("retention-refresh-all");
        let request = aos_proto_types::PlanRefreshAllRetentionRequest {
            cache_id: cache_id.clone(),
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
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_REFRESH_ALL_RETENTION_PATH,
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
                .call::<_, aos_proto_types::OperationResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_REFRESH_ALL_RETENTION_PATH,
                    &reviewed.topology_apply(),
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
                <div><p class="section-kicker">"Re-resolve signed catalogs"</p><h2>"Refresh every subscription"</h2></div>
                <code>{version}</code>
            </div>
            <p>"Creates one operation that resolves every subscription and atomically advances the cache root generation."</p>
            <button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review refresh all"</button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! {
                <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/>
            })}
        </section>
    }
}

fn reload() {
    if let Some(window) = leptos::web_sys::window() {
        let _ = window.location().reload();
    }
}
