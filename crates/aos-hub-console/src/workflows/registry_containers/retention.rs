//! Registry-scoped OCI reachability policy.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::app::refresh;
use crate::components::{format_timestamp, InlineError, ReviewedPlanCard};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

use super::display_or;

/// Renders and reviews the registry's container retention policy.
#[component]
pub(super) fn ContainerRetention(client: ApiClient, registry: String) -> impl IntoView {
    let read_client = client.clone();
    let read_registry = registry.clone();
    let policy = LocalResource::new(move || {
        let client = read_client.clone();
        let registry = read_registry.clone();
        async move {
            client
                .call::<_, aos_proto_types::ContainerRetentionPolicyResponse>(
                    aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_RETENTION_POLICY_PATH,
                    &aos_proto_types::GetContainerRetentionPolicyRequest { registry },
                )
                .await
        }
    });
    view! {
        <Suspense fallback=move || view! { <section class="panel"><p class="loading-row">"Loading container retention policy…"</p></section> }>
            {move || {
                let client = client.clone();
                let registry = registry.clone();
                Suspend::new(async move {
                    match policy.await.as_ref() {
                        Ok(response) => match response.policy.clone() {
                            Some(value) => view! { <RetentionEditor client=client registry=registry policy=value/> }.into_any(),
                            None => view! { <InlineError detail="The Hub omitted the container retention policy.".to_string()/> }.into_any(),
                        },
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn RetentionEditor(
    client: ApiClient,
    registry: String,
    policy: aos_proto_types::ContainerRetentionPolicy,
) -> impl IntoView {
    let untagged = RwSignal::new(policy.untagged_grace_period_secs.to_string());
    let history = RwSignal::new(policy.deleted_tag_history_period_secs.to_string());
    let revisions = RwSignal::new(policy.recent_manual_tag_revisions.to_string());
    let referrers = RwSignal::new(policy.retain_referrers);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let version = policy.resource_version.clone();
    let can_manage = client.allows("registry.configure");
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let untagged_value = match parse_u64(&untagged.get_untracked(), "Untagged grace period") {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let history_value = match parse_u64(&history.get_untracked(), "Deleted-tag history period")
        {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let revision_value = match revisions.get_untracked().trim().parse::<u32>() {
            Ok(value) => value,
            Err(_) => {
                error.set(Some(
                    "Recent manual revisions must be a non-negative integer.".to_string(),
                ));
                return;
            }
        };
        let client = plan_client.clone();
        let key = idempotency_key("container-retention");
        let request = aos_proto_types::PlanSetContainerRetentionPolicyRequest {
            registry: registry.clone(),
            policy: Some(aos_proto_types::ContainerRetentionPolicy {
                registry: registry.clone(),
                untagged_grace_period_secs: untagged_value,
                deleted_tag_history_period_secs: history_value,
                recent_manual_tag_revisions: revision_value,
                retain_referrers: referrers.get_untracked(),
                resource_version: version.clone(),
                updated_at: 0,
            }),
            expected_resource_version: version.clone(),
            idempotency_key: key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::CONTAINER_SERVICE_PLAN_SET_CONTAINER_RETENTION_POLICY_PATH,
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
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ContainerRetentionPolicyResponse>(
                    aos_proto_types::CONTAINER_SERVICE_SET_CONTAINER_RETENTION_POLICY_PATH,
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
        <section class="panel editor-panel"><div class="section-heading"><div><p class="section-kicker">"Registry-scoped reachability"</p><h2>"Container retention"</h2><p>"Tagged images, signed releases, active uploads, and retained referrer artifacts are protected from collection."</p></div></div><div class="resource-identity"><div><span>"Policy version"</span><code>{display_or(&policy.resource_version, "Default policy")}</code></div><div><span>"Last updated"</span><strong>{format_timestamp(policy.updated_at, "Not configured")}</strong></div></div>{can_manage.then(|| view! { <form class="editor-form" on:submit=on_plan><label><span>"Untagged grace (seconds)"</span><input type="number" min="0" required prop:value=move || untagged.get() on:input=move |event| untagged.set(event_target_value(&event))/></label><label><span>"Deleted-tag history (seconds)"</span><input type="number" min="0" required prop:value=move || history.get() on:input=move |event| history.set(event_target_value(&event))/></label><label><span>"Recent manual revisions"</span><input type="number" min="0" required prop:value=move || revisions.get() on:input=move |event| revisions.set(event_target_value(&event))/></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || referrers.get() on:change=move |event| referrers.set(event_target_checked(&event))/><span>"Retain referrer artifacts"</span></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review retention policy"</button></div></form> })}{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section>
    }
}

fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{label} must be a non-negative integer."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_numbers_reject_negative_or_non_numeric_values() {
        assert_eq!(parse_u64("42", "Grace"), Ok(42));
        assert!(parse_u64("-1", "Grace").is_err());
        assert!(parse_u64("forever", "Grace").is_err());
    }
}
