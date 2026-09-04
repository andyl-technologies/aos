//! Registry-derived cache retention subscription workflows.
//!
//! Subscriptions turn selected signed registry releases into GC roots. They
//! remain independent from consumer publication and proactive population.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

use super::cache_manual_roots::ManualRetentionRoots;
use super::cache_retention_refresh::RefreshAllRetention;
use super::cache_root_reasons::RetentionReasons;

#[derive(Clone, Copy)]
struct RetentionFields {
    registry_id: RwSignal<String>,
    current_catalog: RwSignal<bool>,
    all_channels: RwSignal<bool>,
    channels: RwSignal<String>,
    recent_count: RwSignal<String>,
    recent_prereleases: RwSignal<bool>,
    release_tags: RwSignal<String>,
    semver: RwSignal<String>,
    semver_prereleases: RwSignal<bool>,
    all_releases: RwSignal<bool>,
    removal_grace: RwSignal<String>,
    expected_version: RwSignal<String>,
}

impl RetentionFields {
    fn new() -> Self {
        Self {
            registry_id: RwSignal::new(String::new()),
            current_catalog: RwSignal::new(true),
            all_channels: RwSignal::new(false),
            channels: RwSignal::new(String::new()),
            recent_count: RwSignal::new("5".to_string()),
            recent_prereleases: RwSignal::new(false),
            release_tags: RwSignal::new(String::new()),
            semver: RwSignal::new(String::new()),
            semver_prereleases: RwSignal::new(false),
            all_releases: RwSignal::new(false),
            removal_grace: RwSignal::new("86400".to_string()),
            expected_version: RwSignal::new(String::new()),
        }
    }

    fn from_subscription(subscription: &aos_proto_types::RetentionSubscription) -> Self {
        let desired = subscription.desired.clone().unwrap_or_default();
        let selector = desired.selector.unwrap_or_default();
        let channels = selector.channel_targets.unwrap_or_default();
        let recent = selector.recent_releases.unwrap_or_default();
        let semver = selector.semver.unwrap_or_default();
        Self {
            registry_id: RwSignal::new(subscription.registry_id.clone()),
            current_catalog: RwSignal::new(selector.current_catalog),
            all_channels: RwSignal::new(channels.all),
            channels: RwSignal::new(channels.names.join(", ")),
            recent_count: RwSignal::new(
                (recent.count > 0)
                    .then(|| recent.count.to_string())
                    .unwrap_or_default(),
            ),
            recent_prereleases: RwSignal::new(recent.include_prereleases),
            release_tags: RwSignal::new(selector.release_tags.join(", ")),
            semver: RwSignal::new(semver.requirement),
            semver_prereleases: RwSignal::new(semver.include_prereleases),
            all_releases: RwSignal::new(selector.all_releases),
            removal_grace: RwSignal::new(desired.removal_grace_seconds.to_string()),
            expected_version: RwSignal::new(subscription.resource_version.clone()),
        }
    }

    fn desired(self) -> Result<aos_proto_types::RetentionSubscriptionSpec, String> {
        let channel_names = comma_values(&self.channels.get_untracked());
        let release_tags = comma_values(&self.release_tags.get_untracked());
        let recent = optional_positive_u32(&self.recent_count.get_untracked(), "Recent count")?;
        let semver = nonempty(&self.semver.get_untracked());
        let selector = aos_proto_types::RetentionSelector {
            current_catalog: self.current_catalog.get_untracked(),
            channel_targets: (self.all_channels.get_untracked() || !channel_names.is_empty()).then(
                || aos_proto_types::ChannelTargetSelector {
                    all: self.all_channels.get_untracked(),
                    names: channel_names,
                },
            ),
            recent_releases: recent.map(|count| aos_proto_types::RecentReleaseSelector {
                count,
                include_prereleases: self.recent_prereleases.get_untracked(),
            }),
            release_tags,
            semver: semver.map(|requirement| aos_proto_types::SemverRetentionSelector {
                requirement,
                include_prereleases: self.semver_prereleases.get_untracked(),
            }),
            all_releases: self.all_releases.get_untracked(),
        };
        if selector_is_empty(&selector) {
            return Err("Select at least one signed release source".to_string());
        }
        Ok(aos_proto_types::RetentionSubscriptionSpec {
            selector: Some(selector),
            removal_grace_seconds: positive_i64(
                &self.removal_grace.get_untracked(),
                "Removal grace",
            )?,
        })
    }
}

/// Renders retention subscription inventory and the reviewed set editor.
#[component]
pub(super) fn CacheRetentionWorkflow(client: ApiClient, cache_id: String) -> impl IntoView {
    let can_manage = client.allows("cache.retention.manage");
    let read_client = client.clone();
    let read_cache = cache_id.clone();
    let subscriptions = LocalResource::new(move || {
        let client = read_client.clone();
        let cache_id = read_cache.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListRetentionSubscriptionsResponse, _, _, _>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_LIST_RETENTION_SUBSCRIPTIONS_PATH,
                    move |page_token| aos_proto_types::ListRetentionSubscriptionsRequest {
                        cache_id: cache_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.subscriptions, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let view_cache = cache_id.clone();
    let manage_client = client.clone();
    let manage_cache = cache_id.clone();

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"Registry-derived GC roots"</p>
                        <h2>"Retention subscriptions"</h2>
                        <p>
                            "Retain signed catalogs, channels, releases, tags, or semantic-version ranges without changing client cache publication."
                        </p>
                    </div>
                </div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading subscriptions…"</p> }>
                    {move || {
                        let client = view_client.clone();
                        let cache_id = view_cache.clone();
                        Suspend::new(async move {
                        match subscriptions.await.as_ref() {
                            Ok(subscriptions) if subscriptions.is_empty() => view! {
                                <p class="muted">"No registry retention subscriptions."</p>
                            }
                            .into_any(),
                            Ok(subscriptions) => view! {
                                <div class="binding-list">
                                    {subscriptions.iter().cloned().map(|subscription| view! {
                                        <SubscriptionSummary
                                            client=client.clone()
                                            cache_id=cache_id.clone()
                                            subscription=subscription
                                            can_manage=can_manage
                                        />
                                    }).collect_view()}
                                </div>
                            }
                            .into_any(),
                            Err(failure) => view! {
                                <InlineError detail=failure.to_string()/>
                            }
                            .into_any(),
                        }
                        })
                    }}
                </Suspense>
            </section>
            {can_manage.then(|| view! {
                <RetentionEditor client=manage_client.clone() cache_id=manage_cache.clone()/>
                <RefreshAllRetention client=manage_client.clone() cache_id=manage_cache.clone()/>
                <ManualRetentionRoots client=manage_client cache_id=manage_cache/>
            })}
            <RetentionReasons client=client cache_id=cache_id/>
        </div>
    }
}

#[component]
fn SubscriptionSummary(
    client: ApiClient,
    cache_id: String,
    subscription: aos_proto_types::RetentionSubscription,
    can_manage: bool,
) -> impl IntoView {
    let edit_subscription = subscription.clone();
    let registry_id = subscription.registry_id.clone();
    let version = subscription.resource_version.clone();
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{subscription.registry_id}</strong>
                    <code>{subscription.subscription_id}</code>
                </div>
                <StatusBadge
                    state=display_or(&subscription.refresh_state, "not refreshed")
                    positive=subscription.refresh_state == "ready"
                />
            </div>
            <div class="resource-identity">
                <div><span>"Policy version"</span><strong>{subscription.policy_version}</strong></div>
                <div><span>"Resource version"</span><code>{subscription.resource_version}</code></div>
                <div><span>"Refresh operation"</span><code>{display_or(&subscription.current_refresh_id, "none")}</code></div>
            </div>
            {can_manage.then(|| view! { <div class="form-actions">
                <SubscriptionAction
                    client=client.clone()
                    cache_id=cache_id.clone()
                    registry_id=registry_id.clone()
                    version=version.clone()
                    action=SubscriptionActionKind::Refresh
                />
                <SubscriptionAction
                    client=client.clone()
                    cache_id=cache_id.clone()
                    registry_id=registry_id.clone()
                    version=version.clone()
                    action=SubscriptionActionKind::Delete
                />
            </div>
            <details>
                <summary>"Edit this subscription"</summary>
                <RetentionEditor
                    client=client.clone()
                    cache_id=cache_id.clone()
                    initial=edit_subscription
                />
            </details> })}
        </article>
    }
}

#[derive(Clone, Copy)]
enum SubscriptionActionKind {
    Refresh,
    Delete,
}

impl SubscriptionActionKind {
    fn label(self) -> &'static str {
        match self {
            Self::Refresh => "Review refresh",
            Self::Delete => "Review deletion",
        }
    }

    fn button_class(self) -> &'static str {
        match self {
            Self::Refresh => "table-action",
            Self::Delete => "danger-button",
        }
    }
}

#[component]
fn SubscriptionAction(
    client: ApiClient,
    cache_id: String,
    registry_id: String,
    version: String,
    action: SubscriptionActionKind,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |_| {
        let key = idempotency_key(match action {
            SubscriptionActionKind::Refresh => "retention-refresh",
            SubscriptionActionKind::Delete => "retention-delete",
        });
        error.set(None);
        pending.set(None);
        busy.set(true);
        let client = plan_client.clone();
        let cache_id = cache_id.clone();
        let registry_id = registry_id.clone();
        let version = version.clone();
        spawn_local(async move {
            let response = match action {
                SubscriptionActionKind::Refresh => {
                    client
                        .call::<_, aos_proto_types::TopologyPlanResponse>(
                            aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_REFRESH_RETENTION_SUBSCRIPTION_PATH,
                            &aos_proto_types::PlanRefreshRetentionSubscriptionRequest {
                                cache_id,
                                registry_id,
                                expected_resource_version: version,
                                idempotency_key: key.clone(),
                            },
                        )
                        .await
                }
                SubscriptionActionKind::Delete => {
                    client
                        .call::<_, aos_proto_types::TopologyPlanResponse>(
                            aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_DELETE_RETENTION_SUBSCRIPTION_PATH,
                            &aos_proto_types::PlanDeleteRetentionSubscriptionRequest {
                                cache_id,
                                registry_id,
                                expected_resource_version: version,
                                idempotency_key: key.clone(),
                            },
                        )
                        .await
                }
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
                SubscriptionActionKind::Refresh => client
                    .call::<_, aos_proto_types::OperationResponse>(
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_REFRESH_RETENTION_SUBSCRIPTION_PATH,
                        &reviewed.topology_apply(),
                    )
                    .await
                    .map(|_| ()),
                SubscriptionActionKind::Delete => client
                    .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_DELETE_RETENTION_SUBSCRIPTION_PATH,
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

    view! {
        <div class="subworkflow">
            <button
                class=action.button_class()
                type="button"
                disabled=move || busy.get()
                on:click=on_plan
            >
                {action.label()}
            </button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! {
                <ReviewedPlanCard
                    plan=reviewed.plan
                    applying=busy.get()
                    on_apply=on_apply
                    on_cancel=Callback::new(move |()| pending.set(None))
                />
            })}
        </div>
    }
}

#[component]
fn RetentionEditor(
    client: ApiClient,
    cache_id: String,
    #[prop(optional)] initial: Option<aos_proto_types::RetentionSubscription>,
) -> impl IntoView {
    let editing = initial.is_some();
    let fields = initial
        .as_ref()
        .map(RetentionFields::from_subscription)
        .unwrap_or_else(RetentionFields::new);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let desired = match fields.desired() {
            Ok(desired) => desired,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let registry_id = fields.registry_id.get_untracked().trim().to_string();
        if registry_id.is_empty() {
            error.set(Some("Registry stable ID is required".to_string()));
            return;
        }
        let key = idempotency_key("retention-set");
        let request = aos_proto_types::PlanRetentionSubscriptionRequest {
            cache_id: cache_id.clone(),
            registry_id,
            desired: Some(desired),
            expected_resource_version: fields.expected_version.get_untracked().trim().to_string(),
            idempotency_key: key.clone(),
        };
        error.set(None);
        pending.set(None);
        busy.set(true);
        let client = plan_client.clone();
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_SET_RETENTION_SUBSCRIPTION_PATH,
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
                .call::<_, aos_proto_types::RetentionSubscriptionResponse>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_SET_RETENTION_SUBSCRIPTION_PATH,
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
                <div><p class="section-kicker">"Signed release selectors"</p><h2>{if editing { "Edit subscription" } else { "Create subscription" }}</h2></div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label><span>"Registry stable ID"</span><input required prop:value=move || fields.registry_id.get() on:input=move |event| fields.registry_id.set(event_target_value(&event))/></label>
                <label><span>"Expected version (empty when creating)"</span><input prop:value=move || fields.expected_version.get() on:input=move |event| fields.expected_version.set(event_target_value(&event))/></label>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || fields.current_catalog.get()
                        on:change=move |event| fields.current_catalog.set(event_target_checked(&event))
                    />
                    <span>"Current signed catalog"</span>
                </label>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || fields.all_channels.get()
                        on:change=move |event| fields.all_channels.set(event_target_checked(&event))
                    />
                    <span>"All channels"</span>
                </label>
                <label><span>"Channel names (comma-separated)"</span><input prop:value=move || fields.channels.get() on:input=move |event| fields.channels.set(event_target_value(&event))/></label>
                <label><span>"Recent releases"</span><input type="number" min="1" prop:value=move || fields.recent_count.get() on:input=move |event| fields.recent_count.set(event_target_value(&event))/></label>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || fields.recent_prereleases.get()
                        on:change=move |event| fields.recent_prereleases.set(event_target_checked(&event))
                    />
                    <span>"Include recent prereleases"</span>
                </label>
                <label><span>"Release tags (comma-separated)"</span><input prop:value=move || fields.release_tags.get() on:input=move |event| fields.release_tags.set(event_target_value(&event))/></label>
                <label><span>"Semantic-version requirement"</span><input placeholder=">=1.0, <2.0" prop:value=move || fields.semver.get() on:input=move |event| fields.semver.set(event_target_value(&event))/></label>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || fields.semver_prereleases.get()
                        on:change=move |event| fields.semver_prereleases.set(event_target_checked(&event))
                    />
                    <span>"Include matching prereleases"</span>
                </label>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || fields.all_releases.get()
                        on:change=move |event| fields.all_releases.set(event_target_checked(&event))
                    />
                    <span>"Retain all releases"</span>
                </label>
                <label><span>"Removal grace (seconds)"</span><input type="number" min="1" required prop:value=move || fields.removal_grace.get() on:input=move |event| fields.removal_grace.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Review subscription"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! {
                <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/>
            })}
        </section>
    }
}

fn selector_is_empty(selector: &aos_proto_types::RetentionSelector) -> bool {
    !selector.current_catalog
        && selector.channel_targets.is_none()
        && selector.recent_releases.is_none()
        && selector.release_tags.is_empty()
        && selector.semver.is_none()
        && !selector.all_releases
}

fn comma_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn optional_positive_u32(value: &str, label: &str) -> Result<Option<u32>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .map(Some)
        .ok_or_else(|| format!("{label} must be a positive integer"))
}

fn positive_i64(value: &str, label: &str) -> Result<i64, String> {
    value
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label} must be a positive integer"))
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn reload() {
    crate::app::refresh();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_trim_lists_and_require_positive_numbers() {
        assert_eq!(
            comma_values("stable, beta, ,nightly"),
            ["stable", "beta", "nightly"]
        );
        assert_eq!(optional_positive_u32("5", "Count"), Ok(Some(5)));
        assert!(optional_positive_u32("0", "Count").is_err());
    }
}
