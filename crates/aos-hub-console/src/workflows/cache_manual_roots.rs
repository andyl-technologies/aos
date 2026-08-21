//! Operator-created cache retention roots and lease inventory.
//!
//! Manual roots protect one store object independently from registry-derived
//! subscriptions. An optional lease gives that exception an explicit expiry.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

/// Renders manual retention roots and their reviewed creation editor.
#[component]
pub(super) fn ManualRetentionRoots(client: ApiClient, cache_id: String) -> impl IntoView {
    let read_client = client.clone();
    let read_cache = cache_id.clone();
    let roots = LocalResource::new(move || {
        let client = read_client.clone();
        let cache_id = read_cache.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListRetentionRootsResponse, _, _, _>(
                    aos_proto_types::BINARY_CACHE_SERVICE_LIST_RETENTION_ROOTS_PATH,
                    move |page_token| aos_proto_types::ListRetentionRootsRequest {
                        cache_id: cache_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.roots, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let view_cache = cache_id.clone();

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Operator exceptions"</p>
                    <h2>"Manual roots and leases"</h2>
                    <p>
                        "Protect an exact store object permanently or until a Unix timestamp. GC records the operator reason with the root."
                    </p>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading manual roots…"</p> }>
                {move || {
                    let client = view_client.clone();
                    let cache_id = view_cache.clone();
                    Suspend::new(async move {
                    match roots.await.as_ref() {
                        Ok(roots) if roots.is_empty() => view! {
                            <p class="muted">"No manual retention roots."</p>
                        }
                        .into_any(),
                        Ok(roots) => view! {
                            <div class="binding-list">
                                {roots.iter().cloned().map(|root| view! {
                                    <ManualRootSummary client=client.clone() cache_id=cache_id.clone() root=root/>
                                }).collect_view()}
                            </div>
                        }
                        .into_any(),
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                    })
                }}
            </Suspense>
            <ManualRootCreate client=client cache_id=cache_id/>
        </section>
    }
}

#[component]
fn ManualRootSummary(
    client: ApiClient,
    cache_id: String,
    root: aos_proto_types::ManualRetentionRoot,
) -> impl IntoView {
    let lease = root.current_lease.clone();
    let root_id = root.root_id.clone();
    let version = root.resource_version.clone();
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{root.store_hash}</strong><code>{root.root_id}</code></div>
                <StatusBadge
                    state=lease.as_ref().map(|lease| lease.state.clone()).unwrap_or_else(|| "permanent".to_string())
                    positive=lease.as_ref().is_none_or(|lease| lease.state == "active")
                />
            </div>
            <p>{root.reason}</p>
            <div class="resource-identity">
                <div><span>"Created by"</span><strong>{root.created_by}</strong></div>
                <div><span>"Created"</span><strong>{root.created_at}</strong></div>
                <div><span>"Resource version"</span><code>{root.resource_version}</code></div>
                {lease.clone().map(|lease| view! {
                    <div><span>"Lease expires"</span><strong>{lease.expires_at}</strong></div>
                    <div><span>"Lease ID"</span><code>{lease.lease_id}</code></div>
                })}
            </div>
            <div class="form-actions">
                <RootAction
                    client=client.clone()
                    cache_id=cache_id.clone()
                    root_id=root_id.clone()
                    lease_id=String::new()
                    version=version.clone()
                    action=RootActionKind::Renew
                />
                {lease.map(|lease| view! {
                    <RootAction
                        client=client.clone()
                        cache_id=cache_id.clone()
                        root_id=root_id.clone()
                        lease_id=lease.lease_id
                        version=version.clone()
                        action=RootActionKind::Revoke
                    />
                })}
                <RootAction
                    client=client
                    cache_id=cache_id
                    root_id=root_id
                    lease_id=String::new()
                    version=version
                    action=RootActionKind::Delete
                />
            </div>
        </article>
    }
}

#[derive(Clone, Copy)]
enum RootActionKind {
    Renew,
    Revoke,
    Delete,
}

impl RootActionKind {
    fn label(self) -> &'static str {
        match self {
            Self::Renew => "Review lease renewal",
            Self::Revoke => "Review lease revocation",
            Self::Delete => "Review root deletion",
        }
    }

    fn class(self) -> &'static str {
        match self {
            Self::Renew => "table-action",
            Self::Revoke | Self::Delete => "danger-button",
        }
    }
}

#[component]
fn RootAction(
    client: ApiClient,
    cache_id: String,
    root_id: String,
    lease_id: String,
    version: String,
    action: RootActionKind,
) -> impl IntoView {
    let expires_at = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |_| {
        let expires = if matches!(action, RootActionKind::Renew) {
            match required_timestamp(&expires_at.get_untracked()) {
                Ok(value) => Some(value),
                Err(detail) => {
                    error.set(Some(detail));
                    return;
                }
            }
        } else {
            None
        };
        let key = idempotency_key(match action {
            RootActionKind::Renew => "retention-lease-renew",
            RootActionKind::Revoke => "retention-lease-revoke",
            RootActionKind::Delete => "manual-root-delete",
        });
        let client = plan_client.clone();
        let cache_id = cache_id.clone();
        let root_id = root_id.clone();
        let lease_id = lease_id.clone();
        let version = version.clone();
        error.set(None);
        pending.set(None);
        busy.set(true);
        spawn_local(async move {
            let response = match action {
                RootActionKind::Renew => client
                    .call::<_, aos_proto_types::TopologyPlanResponse>(
                        aos_proto_types::BINARY_CACHE_SERVICE_PLAN_RENEW_RETENTION_LEASE_PATH,
                        &aos_proto_types::PlanRetentionLeaseRequest {
                            cache_id,
                            root_id,
                            lease_id: String::new(),
                            expires_at: expires,
                            expected_resource_version: version,
                            idempotency_key: key.clone(),
                        },
                    )
                    .await,
                RootActionKind::Revoke => client
                    .call::<_, aos_proto_types::TopologyPlanResponse>(
                        aos_proto_types::BINARY_CACHE_SERVICE_PLAN_REVOKE_RETENTION_LEASE_PATH,
                        &aos_proto_types::PlanRevokeRetentionLeaseRequest {
                            cache_id,
                            lease_id,
                            expected_resource_version: version,
                            idempotency_key: key.clone(),
                        },
                    )
                    .await,
                RootActionKind::Delete => client
                    .call::<_, aos_proto_types::TopologyPlanResponse>(
                        aos_proto_types::BINARY_CACHE_SERVICE_PLAN_DELETE_MANUAL_RETENTION_ROOT_PATH,
                        &aos_proto_types::PlanDeleteManualRetentionRootRequest {
                            cache_id,
                            root_id,
                            expected_resource_version: version,
                            idempotency_key: key.clone(),
                        },
                    )
                    .await,
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
                RootActionKind::Renew => client
                    .call::<_, aos_proto_types::RetentionLeaseResponse>(
                        aos_proto_types::BINARY_CACHE_SERVICE_RENEW_RETENTION_LEASE_PATH,
                        &reviewed.cache_plan_apply(),
                    )
                    .await
                    .map(|_| ()),
                RootActionKind::Revoke => client
                    .call::<_, aos_proto_types::RetentionLeaseResponse>(
                        aos_proto_types::BINARY_CACHE_SERVICE_REVOKE_RETENTION_LEASE_PATH,
                        &reviewed.cache_plan_apply(),
                    )
                    .await
                    .map(|_| ()),
                RootActionKind::Delete => client
                    .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                        aos_proto_types::BINARY_CACHE_SERVICE_DELETE_MANUAL_RETENTION_ROOT_PATH,
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
            {matches!(action, RootActionKind::Renew).then(|| view! {
                <label>
                    <span>"New lease expiry (Unix timestamp)"</span>
                    <input type="number" min="1" required prop:value=move || expires_at.get() on:input=move |event| expires_at.set(event_target_value(&event))/>
                </label>
            })}
            <button class=action.class() type="button" disabled=move || busy.get() on:click=on_plan>
                {action.label()}
            </button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! {
                <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/>
            })}
        </div>
    }
}

#[component]
fn ManualRootCreate(client: ApiClient, cache_id: String) -> impl IntoView {
    let store_hash = RwSignal::new(String::new());
    let reason = RwSignal::new(String::new());
    let lease_until = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let store_hash_value = store_hash.get_untracked().trim().to_string();
        let reason_value = reason.get_untracked().trim().to_string();
        if store_hash_value.is_empty() || reason_value.is_empty() {
            error.set(Some(
                "Store hash and operator reason are required".to_string(),
            ));
            return;
        }
        let lease = match optional_timestamp(&lease_until.get_untracked()) {
            Ok(lease) => lease,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let key = idempotency_key("manual-root-create");
        let request = aos_proto_types::PlanManualRetentionRootRequest {
            cache_id: cache_id.clone(),
            store_hash: store_hash_value,
            reason: reason_value,
            lease_until: lease,
            idempotency_key: key.clone(),
            expected_resource_version: String::new(),
        };
        let client = plan_client.clone();
        error.set(None);
        pending.set(None);
        busy.set(true);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_CREATE_MANUAL_RETENTION_ROOT_PATH,
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
                .call::<_, aos_proto_types::RetentionRootResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_CREATE_MANUAL_RETENTION_ROOT_PATH,
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
        <section class="subworkflow">
            <h4>"Create manual root"</h4>
            <form class="editor-form" on:submit=on_plan>
                <label>
                    <span>"Store hash"</span>
                    <input required prop:value=move || store_hash.get() on:input=move |event| store_hash.set(event_target_value(&event))/>
                </label>
                <label>
                    <span>"Operator reason"</span>
                    <input required prop:value=move || reason.get() on:input=move |event| reason.set(event_target_value(&event))/>
                </label>
                <label>
                    <span>"Lease expiry as Unix timestamp (optional)"</span>
                    <input type="number" min="1" prop:value=move || lease_until.get() on:input=move |event| lease_until.set(event_target_value(&event))/>
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Review manual root"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! {
                <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/>
            })}
        </section>
    }
}

fn optional_timestamp(value: &str) -> Result<Option<i64>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<i64>()
        .ok()
        .filter(|timestamp| *timestamp > 0)
        .map(Some)
        .ok_or_else(|| "Lease expiry must be a positive Unix timestamp".to_string())
}

fn required_timestamp(value: &str) -> Result<i64, String> {
    optional_timestamp(value)?.ok_or_else(|| "Lease expiry is required".to_string())
}

fn reload() {
    crate::app::refresh();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_lease_timestamp_is_positive() {
        assert_eq!(optional_timestamp(""), Ok(None));
        assert_eq!(optional_timestamp("100"), Ok(Some(100)));
        assert!(optional_timestamp("0").is_err());
    }
}
