//! Registry upstream-mirror configuration and synchronization.
//!
//! Mirror configuration is exact-version retained state. Source credentials
//! are referenced through immutable secret-provider identifiers and never
//! enter the browser as plaintext. Manual synchronization is a separate,
//! reviewed operation over the currently displayed mirror revision.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{HashValue, HelpTooltip, InlineError, ReviewedPlanCard, StatusBadge, format_timestamp};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::{ApiClient, TransportError};

/// Renders one registry's upstream mirror state and reviewed controls.
#[component]
pub(super) fn RegistryMirrorWorkflow(client: ApiClient, registry_id: String) -> impl IntoView {
    let read_client = client.clone();
    let read_registry = registry_id.clone();
    let mirror = LocalResource::new(move || {
        let client = read_client.clone();
        let registry_id = read_registry.clone();
        async move {
            match client
                .call::<_, aos_proto_types::RegistryMirrorResponse>(
                    aos_proto_types::REGISTRY_MIRROR_SERVICE_GET_REGISTRY_MIRROR_PATH,
                    &aos_proto_types::GetRegistryMirrorRequest { registry_id },
                )
                .await
            {
                Ok(response) => Ok(response.mirror),
                Err(TransportError::Http { status: 404, .. }) => Ok(None),
                Err(failure) => Err(failure.to_string()),
            }
        }
    });

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Verified upstream replication"</p>
                    <h2>"Registry mirror"<HelpTooltip term="Registry mirror" summary="Full mirrors synchronize on a schedule. Pull-through mirrors fetch verified objects on demand."/></h2>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading mirror…"</p> }>
                {move || {
                    let client = client.clone();
                    let registry_id = registry_id.clone();
                    Suspend::new(async move {
                        match mirror.await.as_ref() {
                            Ok(current) => view! {
                                <MirrorEditor
                                    client=client
                                    registry_id=registry_id
                                    current=current.clone()
                                />
                            }
                            .into_any(),
                            Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
        </section>
    }
}

#[component]
fn MirrorEditor(
    client: ApiClient,
    registry_id: String,
    current: Option<aos_proto_types::RegistryMirror>,
) -> impl IntoView {
    let can_manage = client.allows("registry.configure");
    let existing = current.clone().unwrap_or_default();
    let source_url = RwSignal::new(existing.source_url);
    let refspec = RwSignal::new(existing.refspec);
    let auth_secret_ref = RwSignal::new(existing.auth_secret_ref);
    let interval_seconds = RwSignal::new(existing.interval_seconds.to_string());
    let signature_policy = RwSignal::new(default_string(existing.signature_policy, "required"));
    let mode = RwSignal::new(mode_name(existing.mode).to_string());
    let expected_version = current
        .as_ref()
        .map(|mirror| mirror.resource_version.clone());
    let has_current = expected_version.is_some();

    let set_pending = RwSignal::new(None::<PendingPlan>);
    let remove_pending = RwSignal::new(None::<PendingPlan>);
    let sync_pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let plan_client = client.clone();
    let plan_registry = registry_id.clone();
    let plan_version = expected_version.clone();
    let on_plan_set = move |event: SubmitEvent| {
        event.prevent_default();

        let source = match validate_source_url(&source_url.get_untracked()) {
            Ok(source) => source,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let interval = match parse_interval(&interval_seconds.get_untracked()) {
            Ok(interval) => interval,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };

        let key = idempotency_key("registry-mirror-set");
        let request = aos_proto_types::PlanRegistryMirrorMutationRequest {
            registry_id: plan_registry.clone(),
            desired: Some(aos_proto_types::RegistryMirrorSpec {
                source_url: source,
                refspec: refspec.get_untracked().trim().to_string(),
                auth_secret_ref: auth_secret_ref.get_untracked().trim().to_string(),
                interval_seconds: interval,
                signature_policy: signature_policy.get_untracked(),
                mode: mode_value(&mode.get_untracked()),
            }),
            expected_resource_version: plan_version.clone(),
            update_mask: vec!["desired".to_string()],
            idempotency_key: key.clone(),
        };
        remove_pending.set(None);
        sync_pending.set(None);
        begin_plan(
            plan_client.clone(),
            aos_proto_types::REGISTRY_MIRROR_SERVICE_PLAN_SET_REGISTRY_MIRROR_PATH,
            request,
            key,
            set_pending,
            error,
            busy,
        );
    };

    let remove_client = client.clone();
    let remove_registry = registry_id.clone();
    let remove_version = expected_version.clone();
    let on_plan_remove = move |_| {
        let Some(version) = remove_version.clone() else {
            return;
        };
        let key = idempotency_key("registry-mirror-remove");
        let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
            stable_id: remove_registry.clone(),
            expected_resource_version: Some(version),
            idempotency_key: key.clone(),
        };
        set_pending.set(None);
        sync_pending.set(None);
        begin_plan(
            remove_client.clone(),
            aos_proto_types::REGISTRY_MIRROR_SERVICE_PLAN_DELETE_REGISTRY_MIRROR_PATH,
            request,
            key,
            remove_pending,
            error,
            busy,
        );
    };

    let sync_client = client.clone();
    let sync_registry = registry_id.clone();
    let sync_version = expected_version.clone();
    let on_plan_sync = move |_| {
        let Some(version) = sync_version.clone() else {
            return;
        };
        let key = idempotency_key("registry-mirror-sync");
        let request = aos_proto_types::PlanSyncRegistryMirrorRequest {
            registry_id: sync_registry.clone(),
            expected_resource_version: version,
            idempotency_key: key.clone(),
        };
        set_pending.set(None);
        remove_pending.set(None);
        begin_plan(
            sync_client.clone(),
            aos_proto_types::REGISTRY_MIRROR_SERVICE_PLAN_SYNC_REGISTRY_MIRROR_PATH,
            request,
            key,
            sync_pending,
            error,
            busy,
        );
    };

    let apply_set = apply_topology::<aos_proto_types::RegistryMirrorResponse>(
        client.clone(),
        aos_proto_types::REGISTRY_MIRROR_SERVICE_SET_REGISTRY_MIRROR_PATH,
        set_pending,
        error,
        busy,
    );
    let apply_remove = apply_delete(client.clone(), remove_pending, error, busy);
    let apply_sync = apply_topology::<aos_proto_types::OperationResponse>(
        client,
        aos_proto_types::REGISTRY_MIRROR_SERVICE_SYNC_REGISTRY_MIRROR_PATH,
        sync_pending,
        error,
        busy,
    );

    view! {
        {current.map(|mirror| view! { <MirrorStatus mirror=mirror/> })}
        {(!has_current).then(|| view! { <p class="muted">"No upstream mirror is configured. Add one to synchronize content from another registry."</p> })}
        {can_manage.then(|| view! {
        <details class="advanced-controls"><summary>{if has_current { "Edit upstream mirror" } else { "Configure upstream mirror" }}</summary>
        <form class="editor-form" on:submit=on_plan_set>
            <label>
                <span>"HTTPS source URL"</span>
                <input
                    required
                    type="url"
                    prop:value=move || source_url.get()
                    on:input=move |event| source_url.set(event_target_value(&event))
                />
            </label>
            <label>
                <span>"Git refspec (optional)"</span>
                <input
                    prop:value=move || refspec.get()
                    on:input=move |event| refspec.set(event_target_value(&event))
                />
            </label>
            <label>
                <span>"Authentication secret"</span>
                <input
                    prop:value=move || auth_secret_ref.get()
                    on:input=move |event| auth_secret_ref.set(event_target_value(&event))
                />
                <small>"Optional immutable secret version reference for a private upstream. Do not enter a password or token here."</small>
            </label>
            <label>
                <span>"Synchronization interval (seconds)"</span>
                <input
                    required
                    type="number"
                    min="0"
                    prop:value=move || interval_seconds.get()
                    on:input=move |event| interval_seconds.set(event_target_value(&event))
                />
            </label>
            <label>
                <span>"Signature policy"</span>
                <select
                    prop:value=move || signature_policy.get()
                    on:change=move |event| signature_policy.set(event_target_value(&event))
                >
                    <option value="required">"Required"</option>
                    <option value="optional">"Optional"</option>
                    <option value="disabled">"Disabled"</option>
                </select>
            </label>
            <label>
                <span>"Mirror mode"</span>
                <select
                    prop:value=move || mode.get()
                    on:change=move |event| mode.set(event_target_value(&event))
                >
                    <option value="full">"Full synchronization"</option>
                    <option value="pull-through">"Pull through"</option>
                </select>
            </label>
            <button class="secondary-button" type="submit" disabled=move || busy.get()>
                "Review mirror configuration"
            </button>
        </form>
        <PlanReview pending=set_pending busy=busy on_apply=apply_set/>
        </details>
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        {has_current.then(|| view! {
        <div class="form-actions">
            <button
                class="secondary-button"
                type="button"
                disabled=move || busy.get() || !has_current
                on:click=on_plan_sync
            >
                "Review synchronization"
            </button>
            <button
                class="danger-button"
                type="button"
                disabled=move || busy.get() || !has_current
                on:click=on_plan_remove
            >
                "Review mirror removal"
            </button>
        </div>
        <PlanReview pending=sync_pending busy=busy on_apply=apply_sync/>
        <PlanReview pending=remove_pending busy=busy on_apply=apply_remove/>
        })}
        })}
    }
}

#[component]
fn MirrorStatus(mirror: aos_proto_types::RegistryMirror) -> impl IntoView {
    view! {
        <div class="resource-identity">
            <div><span>"Upstream"</span><code>{mirror.source_url}</code></div>
            <div><span>"Mode"</span><strong>{if mode_name(mirror.mode) == "full" { "Full synchronization" } else { "Pull through" }}</strong></div>
            <div>
                <span>"State"</span>
                <StatusBadge state=mirror.state.clone() positive=mirror.state == "ready"/>
            </div>
            <div>
                <span>"Observed commit"</span>
                {if mirror.observed_commit.is_empty() { view! { <span>"not synchronized"</span> }.into_any() } else { view! { <HashValue value=mirror.observed_commit/> }.into_any() }}
            </div>
            <div>
                <span>"Last synchronization"</span>
                <strong>{format_timestamp(mirror.last_sync_at, "Never")}</strong>
            </div>
            <div>
                <span>"Version"</span>
                <code>{mirror.resource_version}</code>
            </div>
        </div>
        {(!mirror.error.is_empty()).then(|| view! { <InlineError detail=mirror.error/> })}
    }
}

fn begin_plan<RequestMessage>(
    client: ApiClient,
    path: &'static str,
    request: RequestMessage,
    key: String,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) where
    RequestMessage: serde::Serialize + 'static,
{
    error.set(None);
    pending.set(None);
    busy.set(true);

    spawn_local(async move {
        let result = client
            .call(path, &request)
            .await
            .map_err(|failure| failure.to_string())
            .and_then(|response| PendingPlan::from_response(response, key));
        match result {
            Ok(reviewed) => pending.set(Some(reviewed)),
            Err(detail) => error.set(Some(detail)),
        }
        busy.set(false);
    });
}

fn apply_topology<ResponseMessage>(
    client: ApiClient,
    path: &'static str,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) -> Callback<()>
where
    ResponseMessage: serde::de::DeserializeOwned + 'static,
{
    Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);

        spawn_local(async move {
            match client
                .call::<_, ResponseMessage>(path, &reviewed.topology_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}

fn apply_delete(
    client: ApiClient,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) -> Callback<()> {
    Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);

        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                    aos_proto_types::REGISTRY_MIRROR_SERVICE_DELETE_REGISTRY_MIRROR_PATH,
                    &reviewed.delete_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}

#[component]
fn PlanReview(
    pending: RwSignal<Option<PendingPlan>>,
    busy: RwSignal<bool>,
    on_apply: Callback<()>,
) -> impl IntoView {
    view! {
        {move || pending.get().map(|reviewed| view! {
            <ReviewedPlanCard
                plan=reviewed.plan
                applying=busy.get()
                on_apply=on_apply
                on_cancel=Callback::new(move |()| pending.set(None))
            />
        })}
    }
}

fn validate_source_url(value: &str) -> Result<String, String> {
    let parsed = leptos::web_sys::Url::new(value.trim())
        .map_err(|_| "Mirror source URL is malformed".to_string())?;
    if parsed.protocol() != "https:"
        || parsed.host().is_empty()
        || !parsed.username().is_empty()
        || !parsed.password().is_empty()
        || !parsed.hash().is_empty()
    {
        return Err(
            "Mirror source must be an absolute HTTPS URL without credentials or a fragment"
                .to_string(),
        );
    }
    Ok(parsed.href())
}

fn parse_interval(value: &str) -> Result<i64, String> {
    value
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|seconds| *seconds >= 0)
        .ok_or_else(|| "Synchronization interval must be a non-negative number".to_string())
}

fn mode_value(value: &str) -> i32 {
    match value {
        "pull-through" => aos_proto_types::RegistryMirrorMode::PullThrough as i32,
        _ => aos_proto_types::RegistryMirrorMode::Full as i32,
    }
}

fn mode_name(value: i32) -> &'static str {
    if value == aos_proto_types::RegistryMirrorMode::PullThrough as i32 {
        "pull-through"
    } else {
        "full"
    }
}

fn default_string(value: String, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

fn reload() {
    crate::app::refresh();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_reject_negative_and_non_numeric_values() {
        assert_eq!(parse_interval("0"), Ok(0));
        assert_eq!(parse_interval("3600"), Ok(3600));
        assert!(parse_interval("-1").is_err());
        assert!(parse_interval("hourly").is_err());
    }
}
