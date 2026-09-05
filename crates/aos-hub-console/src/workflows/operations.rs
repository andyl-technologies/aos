//! Durable operation inventory and lifecycle controls.
//!
//! Every page resolves its mutable URL locator to an immutable authorization
//! scope before listing work. Instance and organization pages include the
//! complete descendant scope closure; registry and cache pages use the same
//! model so controller work on their subordinate topology remains visible.
//! Cancellation and retry are direct operation state transitions, fenced by
//! the exact resource version displayed during confirmation.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::prelude::*;

use crate::components::{InlineError, StatusBadge};
use crate::mutation::idempotency_key;
use crate::transport::ApiClient;

/// One console surface whose operation scope must be resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OperationSurface {
    /// Deployment-wide operations.
    Instance,
    /// Operations owned by an organization or any descendant resource.
    Organization(String),
    /// Operations owned by a registry's immutable scope.
    Registry(String),
    /// Operations owned by a cache's immutable scope.
    Cache(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationContext {
    scope: String,
    label: String,
}

/// Renders the complete durable-operation workflow for one console surface.
#[component]
pub(super) fn OperationsWorkflow(client: ApiClient, surface: OperationSurface) -> impl IntoView {
    let context_client = client.clone();
    let context = LocalResource::new(move || {
        let client = context_client.clone();
        let surface = surface.clone();
        async move { resolve_context(&client, surface).await }
    });
    let view_client = client;

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Resolving operation scope…"</p> }>
            {move || {
                let client = view_client.clone();
                Suspend::new(async move {
                    match context.await.as_ref() {
                        Ok(context) => view! {
                            <OperationInventory client=client context=context.clone()/>
                        }
                        .into_any(),
                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

async fn resolve_context(
    client: &ApiClient,
    surface: OperationSurface,
) -> Result<OperationContext, String> {
    let context = match surface {
        OperationSurface::Instance => OperationContext {
            scope: "instance".to_string(),
            label: "AOS Hub instance".to_string(),
        },
        OperationSurface::Organization(slug) => {
            let response = client
                .call::<_, aos_proto_types::OrganizationResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_GET_ORGANIZATION_PATH,
                    &aos_proto_types::GetOrganizationRequest { slug },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let organization = response
                .organization
                .ok_or_else(|| "the Hub omitted the organization".to_string())?;
            OperationContext {
                scope: organization.authorization_scope_key,
                label: organization.display_name,
            }
        }
        OperationSurface::Registry(slug) => {
            let response = client
                .call::<_, aos_proto_types::GetRegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_GET_REGISTRY_PATH,
                    &aos_proto_types::GetRegistryRequest { slug },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let registry = response
                .registry
                .ok_or_else(|| "the Hub omitted the registry".to_string())?;
            OperationContext {
                scope: registry.authorization_scope_key,
                label: registry.slug,
            }
        }
        OperationSurface::Cache(cache_id) => {
            let response = client
                .call::<_, aos_proto_types::BinaryCacheResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_BINARY_CACHE_PATH,
                    &aos_proto_types::GetBinaryCacheRequest { cache_id },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let cache = response
                .cache
                .ok_or_else(|| "the Hub omitted the binary cache".to_string())?;
            OperationContext {
                scope: cache.authorization_scope_key,
                label: cache.slug,
            }
        }
    };
    if context.scope.is_empty() {
        return Err("the Hub omitted the immutable authorization scope".to_string());
    }
    Ok(context)
}

#[component]
fn OperationInventory(client: ApiClient, context: OperationContext) -> impl IntoView {
    let state = RwSignal::new(String::new());
    let inventory_client = client.clone();
    let inventory_scope = context.scope.clone();
    let operations = LocalResource::new(move || {
        let client = inventory_client.clone();
        let scope = inventory_scope.clone();
        let state = state.get();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListOperationsResponse, _, _, _>(
                    aos_proto_types::OPERATION_SERVICE_LIST_OPERATIONS_PATH,
                    move |page_token| aos_proto_types::ListOperationsRequest {
                        target: None,
                        state: state.clone(),
                        page_size: 100,
                        page_token,
                        authorization_scope_key: scope.clone(),
                    },
                    |response| (response.operations, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client;

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Durable controller work"</p>
                    <h2>"Operations"</h2>
                    <p>{format!("Inspect work owned by {} and its topology descendants.", context.label)}</p>
                </div>
                <label>
                    <span>"State"</span>
                    <select on:change=move |event| state.set(event_target_value(&event))>
                        <option value="">"All states"</option>
                        <option value="pending">"Pending"</option>
                        <option value="running">"Running"</option>
                        <option value="succeeded">"Succeeded"</option>
                        <option value="failed">"Failed"</option>
                        <option value="cancelled">"Cancelled"</option>
                    </select>
                </label>
            </div>
            <div class="resource-identity">
                <div><span>"Authorization scope"</span><code>{context.scope}</code></div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading operations…"</p> }>
                {move || {
                    let client = view_client.clone();
                    Suspend::new(async move {
                        match operations.await.as_ref() {
                            Ok(operations) if operations.is_empty() => view! {
                                <p class="muted">"No operations match this state filter."</p>
                            }
                            .into_any(),
                            Ok(operations) => view! {
                                <div class="binding-list">
                                    {operations.iter().cloned().map(|operation| view! {
                                        <OperationCard client=client.clone() operation=operation/>
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
    }
}

#[component]
fn OperationCard(client: ApiClient, operation: aos_proto_types::OperationDetail) -> impl IntoView {
    let reference = operation.operation.clone().unwrap_or_default();
    let positive = reference.state == "succeeded";
    let can_cancel = matches!(reference.state.as_str(), "pending" | "running");
    let can_retry = matches!(reference.state.as_str(), "failed" | "cancelled");
    let progress = operation
        .total_units
        .map(|total| format!("{} / {total}", operation.completed_units))
        .unwrap_or_else(|| operation.completed_units.to_string());

    view! {
        <details class="binding-card">
            <summary>
                <div>
                    <span class="resource-kind">"Operation"</span>
                    <h3>{humanize_kind(&reference.kind)}</h3>
                    <span>{format!("Created {}", timestamp(reference.created_at))}</span>
                </div>
                <div class="binding-summary-state">
                    <StatusBadge state=reference.state.clone() positive=positive/>
                </div>
            </summary>
            <div class="binding-details">
                <div class="resource-identity">
                    <div><span>"Operation ID"</span><code>{reference.operation_id.clone()}</code></div>
                    <div><span>"Kind"</span><strong>{reference.kind.clone()}</strong></div>
                    <div><span>"Progress"</span><strong>{progress}</strong></div>
                    <div><span>"Updated"</span><strong>{timestamp(operation.updated_at)}</strong></div>
                    <div><span>"Finished"</span><strong>{operation.finished_at.map(timestamp).unwrap_or_else(|| "Not finished".to_string())}</strong></div>
                    <div><span>"Resource version"</span><code>{operation.resource_version.clone()}</code></div>
                </div>
                <section class="subworkflow">
                    <h4>"Target snapshots"</h4>
                    <div class="binding-list">
                        {operation.targets.into_iter().map(|target| view! {
                            <div class="compact-list-row">
                                <div>
                                    <strong>{target.role.clone()}</strong>
                                    <code>{target_label(&target)}</code>
                                </div>
                                <span>{generation_label(&target)}</span>
                            </div>
                        }).collect_view()}
                    </div>
                </section>
                {(!operation.error.is_empty()).then(|| view! {
                    <div class="operation-failure"><strong>"Operation failed"</strong><p>{operation.error}</p></div>
                })}
                <div class="form-actions">
                    {can_cancel.then(|| view! {
                        <OperationAction
                            client=client.clone()
                            operation_id=reference.operation_id.clone()
                            resource_version=operation.resource_version.clone()
                            action=OperationActionKind::Cancel
                        />
                    })}
                    {can_retry.then(|| view! {
                        <OperationAction
                            client=client
                            operation_id=reference.operation_id
                            resource_version=operation.resource_version
                            action=OperationActionKind::Retry
                        />
                    })}
                </div>
            </div>
        </details>
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationActionKind {
    Cancel,
    Retry,
}

impl OperationActionKind {
    fn label(self) -> &'static str {
        match self {
            Self::Cancel => "Cancel operation",
            Self::Retry => "Retry operation",
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Cancel => aos_proto_types::OPERATION_SERVICE_CANCEL_OPERATION_PATH,
            Self::Retry => aos_proto_types::OPERATION_SERVICE_RETRY_OPERATION_PATH,
        }
    }
}

#[component]
fn OperationAction(
    client: ApiClient,
    operation_id: String,
    resource_version: String,
    action: OperationActionKind,
) -> impl IntoView {
    let confirming = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let exact_operation_id = operation_id.clone();
    let exact_version = resource_version.clone();
    let on_apply = Callback::new(move |()| {
        let client = client.clone();
        let operation_id = exact_operation_id.clone();
        let expected_resource_version = exact_version.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            let request = aos_proto_types::MutateOperationRequest {
                operation_id,
                expected_resource_version,
                idempotency_key: idempotency_key(match action {
                    OperationActionKind::Cancel => "operation-cancel",
                    OperationActionKind::Retry => "operation-retry",
                }),
            };
            match client
                .call::<_, aos_proto_types::OperationDetailResponse>(action.path(), &request)
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="subworkflow">
            <button
                class=if matches!(action, OperationActionKind::Cancel) { "danger-button" } else { "table-action" }
                type="button"
                disabled=move || busy.get()
                on:click=move |_| confirming.set(true)
            >
                {action.label()}
            </button>
            {move || confirming.get().then(|| view! {
                <div class="review-card">
                    <p><strong>{format!("Confirm {}", action.label().to_lowercase())}</strong></p>
                    <p>"This transition is fenced to the exact operation version shown below. A concurrent update will reject it."</p>
                    <div class="resource-identity">
                        <div><span>"Operation"</span><code>{operation_id.clone()}</code></div>
                        <div><span>"Expected version"</span><code>{resource_version.clone()}</code></div>
                    </div>
                    <div class="review-actions">
                        <button class="secondary-button" type="button" disabled=move || busy.get() on:click=move |_| confirming.set(false)>"Back"</button>
                        <button class=if matches!(action, OperationActionKind::Cancel) { "danger-button" } else { "button" } type="button" disabled=move || busy.get() on:click=move |_| on_apply.run(())>
                            {if busy.get() { "Applying…" } else { "Confirm" }}
                        </button>
                    </div>
                </div>
            })}
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        </div>
    }
}

fn target_label(target: &aos_proto_types::OperationTarget) -> String {
    use aos_proto_types::operation_target::Target;

    match target.target.as_ref() {
        Some(Target::RegistryId(id)) => format!("registry:{id}"),
        Some(Target::BinaryCacheId(id)) => format!("cache:{id}"),
        Some(Target::PlacementId(id)) => format!("placement:{id}"),
        Some(Target::DomainId(id)) => format!("domain:{id}"),
        Some(Target::NetworkPolicyId(id)) => format!("boundary:{id}"),
        Some(Target::EndpointId(id)) => format!("endpoint:{id}"),
        Some(Target::GatewayId(id)) => format!("gateway:{id}"),
        Some(Target::RouteId(id)) => format!("route:{id}"),
        Some(Target::PlacementPolicyId(id)) => format!("policy:{id}"),
        Some(Target::RetentionSubscriptionId(id)) => format!("retention:{id}"),
        Some(Target::PopulationTargetId(id)) => format!("population:{id}"),
        Some(Target::CacheGcGenerationId(id)) => format!("gc-generation:{id}"),
        Some(Target::BindingId(id)) => format!("storage-binding:{id}"),
        None => "unknown target".to_string(),
    }
}

fn generation_label(target: &aos_proto_types::OperationTarget) -> String {
    match (target.generation_key, target.configuration_digest.as_str()) {
        (0, "") => "current identity".to_string(),
        (generation, "") => format!("generation {generation}"),
        (generation, digest) => format!("generation {generation} · {}", short_digest(digest)),
    }
}

fn humanize_kind(kind: &str) -> String {
    kind.replace('_', " ")
}

fn short_digest(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

fn timestamp(value: i64) -> String {
    crate::components::format_timestamp(value, "Not recorded")
}

fn reload() {
    crate::app::refresh();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_labels_cover_the_closed_target_set() {
        let target = aos_proto_types::OperationTarget {
            role: "primary".to_string(),
            target: Some(aos_proto_types::operation_target::Target::BinaryCacheId(
                "cache:abc".to_string(),
            )),
            generation_key: 4,
            configuration_digest: "0123456789abcdef".to_string(),
        };
        assert_eq!(target_label(&target), "cache:cache:abc");
        assert_eq!(generation_label(&target), "generation 4 · 0123456789ab");
    }
}
