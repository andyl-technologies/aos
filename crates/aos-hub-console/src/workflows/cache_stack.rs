//! Registry-owned signed consumer-cache stack workflows.
//!
//! The registry owns ordering and signs the resulting consumer configuration.
//! Stack entries may reference shared managed caches or external HTTP origins.
//! Every mutation carries the exact stack version through immutable plan/apply.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HashValue, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

/// Renders a registry's ordered consumer-cache stack and validation result.
#[component]
pub(super) fn RegistryCacheStack(client: ApiClient, registry_id: String) -> impl IntoView {
    let stack = stack_resource(client.clone(), registry_id.clone());
    let validation = validation_resource(client.clone(), registry_id.clone());
    let view_client = client;
    let view_registry = registry_id;

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"Signed consumer configuration"</p>
                        <h2>"Binary cache stack"</h2>
                        <p>
                            "The registry signs this ordered stack. Managed caches remain independent and may be shared by other registries."
                        </p>
                    </div>
                </div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading consumer cache stack…"</p> }>
                    {move || {
                        let client = view_client.clone();
                        let registry_id = view_registry.clone();
                        Suspend::new(async move {
                            match stack.await.as_ref() {
                                Ok(response) => render_stack(
                                    client,
                                    registry_id,
                                    response.stack.clone().unwrap_or_default(),
                                ),
                                Err(failure) => view! {
                                    <InlineError detail=failure.to_string()/>
                                }
                                .into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section>
            <ValidationPanel validation=validation/>
        </div>
    }
}

fn stack_resource(
    client: ApiClient,
    registry_id: String,
) -> LocalResource<
    Result<aos_proto_types::ConsumerCacheStackResponse, crate::transport::TransportError>,
> {
    LocalResource::new(move || {
        let client = client.clone();
        let registry_id = registry_id.clone();
        async move {
            client
                .call(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_GET_CONSUMER_CACHE_STACK_PATH,
                    &aos_proto_types::GetConsumerCacheStackRequest { registry_id },
                )
                .await
        }
    })
}

fn validation_resource(
    client: ApiClient,
    registry_id: String,
) -> LocalResource<
    Result<aos_proto_types::ConsumerCacheStackValidationResponse, crate::transport::TransportError>,
> {
    LocalResource::new(move || {
        let client = client.clone();
        let registry_id = registry_id.clone();
        async move {
            client
                .call(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_VALIDATE_CONSUMER_CACHE_STACK_PATH,
                    &aos_proto_types::GetConsumerCacheStackRequest { registry_id },
                )
                .await
        }
    })
}

fn render_stack(
    client: ApiClient,
    registry_id: String,
    stack: aos_proto_types::ConsumerCacheStack,
) -> AnyView {
    let version = stack.resource_version.clone();
    view! {
        <div class="resource-identity">
            <div><span>"Indexed commit"</span>{if stack.indexed_commit.is_empty() { view! { <span>"not indexed"</span> }.into_any() } else { view! { <HashValue value=stack.indexed_commit/> }.into_any() }}</div>
            <div><span>"Version"</span><code>{display_or(&version, "initial")}</code></div>
        </div>
        <div class="binding-list">
            {stack
                .entries
                .into_iter()
                .map(|entry| view! {
                    <CacheStackEntry
                        client=client.clone()
                        registry_id=registry_id.clone()
                        version=version.clone()
                        entry=entry
                    />
                })
                .collect_view()}
        </div>
        <CacheStackAdd client=client registry_id=registry_id version=version/>
    }
    .into_any()
}

#[component]
fn ValidationPanel(
    validation: LocalResource<
        Result<
            aos_proto_types::ConsumerCacheStackValidationResponse,
            crate::transport::TransportError,
        >,
    >,
) -> impl IntoView {
    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Route and signature checks"</p>
                    <h2>"Stack validation"</h2>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Validating cache stack…"</p> }>
                {move || Suspend::new(async move {
                    match validation.await.as_ref() {
                        Ok(response) => view! {
                            <StatusBadge
                                state=if response.valid { "valid" } else { "invalid" }.to_string()
                                positive=response.valid
                            />
                            <div class="compact-list">
                                {response.errors.iter().map(|value| view! {
                                    <InlineError detail=value.clone()/>
                                }).collect_view()}
                                {response.warnings.iter().map(|value| view! {
                                    <div class="compact-list-row"><span>{value.clone()}</span></div>
                                }).collect_view()}
                            </div>
                        }
                        .into_any(),
                        Err(failure) => view! {
                            <InlineError detail=failure.to_string()/>
                        }
                        .into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn CacheStackEntry(
    client: ApiClient,
    registry_id: String,
    version: String,
    entry: aos_proto_types::ConsumerCacheStackEntry,
) -> impl IntoView {
    let before = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let entry_id = entry.entry_id.clone();

    let on_action = Callback::new(move |operation: &'static str| {
        let change = aos_proto_types::ConsumerCacheChange {
            operation: operation.to_string(),
            entry_id: entry_id.clone(),
            desired: None,
            before_entry_id: if operation == "move" {
                before.get_untracked().trim().to_string()
            } else {
                String::new()
            },
            mirror_with_entry_id: String::new(),
        };
        begin_plan(
            plan_client.clone(),
            registry_id.clone(),
            version.clone(),
            change,
            pending,
            error,
            busy,
        );
    });
    let apply = apply_callback(client, pending, error, busy);
    let move_action = on_action.clone();

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{source_name(&entry)}</strong>
                    <code>{entry.entry_id}</code>
                    <span>{format!(
                        "priority {} · mirror group {}",
                        entry.priority,
                        display_or(&entry.mirror_group_id, "none"),
                    )}</span>
                </div>
                <button
                    class="table-action"
                    type="button"
                    disabled=move || busy.get()
                    on:click=move |_| on_action.run("remove")
                >
                    "Review removal"
                </button>
            </div>
            <div class="form-actions">
                <input
                    placeholder="entry ID to move before"
                    prop:value=move || before.get()
                    on:input=move |event| before.set(event_target_value(&event))
                />
                <button
                    class="table-action"
                    type="button"
                    disabled=move || busy.get()
                    on:click=move |_| move_action.run("move")
                >
                    "Review move"
                </button>
            </div>
            <PlanReview pending=pending error=error busy=busy on_apply=apply/>
        </article>
    }
}

#[component]
fn CacheStackAdd(client: ApiClient, registry_id: String, version: String) -> impl IntoView {
    let source_kind = RwSignal::new("managed".to_string());
    let source_value = RwSignal::new(String::new());
    let before = RwSignal::new(String::new());
    let mirror_with = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let source = match cache_source(&source_kind.get_untracked(), &source_value.get_untracked())
        {
            Ok(source) => source,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let change = aos_proto_types::ConsumerCacheChange {
            operation: "add".to_string(),
            entry_id: String::new(),
            desired: Some(aos_proto_types::ConsumerCacheStackEntry {
                entry_id: String::new(),
                source: Some(source),
                priority: 0,
                mirror_group_id: String::new(),
            }),
            before_entry_id: before.get_untracked().trim().to_string(),
            mirror_with_entry_id: mirror_with.get_untracked().trim().to_string(),
        };
        begin_plan(
            plan_client.clone(),
            registry_id.clone(),
            version.clone(),
            change,
            pending,
            error,
            busy,
        );
    };
    let apply = apply_callback(client, pending, error, busy);

    view! {
        <section class="subworkflow">
            <h4>"Add consumer cache"</h4>
            <form class="editor-form" on:submit=on_plan>
                <label>
                    <span>"Source kind"</span>
                    <select
                        prop:value=move || source_kind.get()
                        on:change=move |event| source_kind.set(event_target_value(&event))
                    >
                        <option value="managed">"Managed cache"</option>
                        <option value="external">"External cache URL"</option>
                    </select>
                </label>
                <label>
                    <span>{move || if source_kind.get() == "managed" {
                        "Cache stable ID"
                    } else {
                        "External HTTP(S) URL"
                    }}</span>
                    <input
                        required
                        prop:value=move || source_value.get()
                        on:input=move |event| source_value.set(event_target_value(&event))
                    />
                </label>
                <label>
                    <span>"Insert before entry (optional)"</span>
                    <input
                        prop:value=move || before.get()
                        on:input=move |event| before.set(event_target_value(&event))
                    />
                </label>
                <label>
                    <span>"Mirror with entry (optional)"</span>
                    <input
                        prop:value=move || mirror_with.get()
                        on:input=move |event| mirror_with.set(event_target_value(&event))
                    />
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    "Review stack change"
                </button>
            </form>
            <PlanReview pending=pending error=error busy=busy on_apply=apply/>
        </section>
    }
}

fn cache_source(
    kind: &str,
    value: &str,
) -> Result<aos_proto_types::consumer_cache_stack_entry::Source, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("A cache stable ID or external URL is required".to_string());
    }
    if kind == "managed" {
        return Ok(
            aos_proto_types::consumer_cache_stack_entry::Source::BinaryCacheId(value.to_string()),
        );
    }
    let url = validate_external_url(value)?;
    Ok(
        aos_proto_types::consumer_cache_stack_entry::Source::External(
            aos_proto_types::ExternalConsumerCache { url },
        ),
    )
}

fn validate_external_url(value: &str) -> Result<String, String> {
    let url = leptos::web_sys::Url::new(value)
        .map_err(|_| "External cache URL is malformed".to_string())?;
    if !matches!(url.protocol().as_str(), "http:" | "https:") {
        return Err("External cache URLs must use HTTP or HTTPS".to_string());
    }
    if url.host().is_empty()
        || !url.username().is_empty()
        || !url.password().is_empty()
        || !url.search().is_empty()
        || !url.hash().is_empty()
    {
        return Err(
            "External cache URLs need a host and cannot contain credentials, query, or fragment"
                .to_string(),
        );
    }
    Ok(url.href())
}

fn begin_plan(
    client: ApiClient,
    registry_id: String,
    version: String,
    change: aos_proto_types::ConsumerCacheChange,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) {
    let key = idempotency_key("cache-stack-change");
    let request = aos_proto_types::PlanCreateConsumerCacheChangesetRequest {
        registry_id,
        change: Some(change),
        expected_resource_version: version,
        idempotency_key: key.clone(),
    };
    error.set(None);
    pending.set(None);
    busy.set(true);
    spawn_local(async move {
        let result = client
            .call(
                aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_CREATE_CONSUMER_CACHE_CHANGESET_PATH,
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
}

fn apply_callback(
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
                .call::<_, aos_proto_types::ConsumerCacheChangesetResponse>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_CREATE_CONSUMER_CACHE_CHANGESET_PATH,
                    &reviewed.topology_apply(),
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
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    on_apply: Callback<()>,
) -> impl IntoView {
    view! {
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
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

fn source_name(entry: &aos_proto_types::ConsumerCacheStackEntry) -> String {
    match entry.source.as_ref() {
        Some(aos_proto_types::consumer_cache_stack_entry::Source::BinaryCacheId(id)) => {
            format!("Managed cache · {id}")
        }
        Some(aos_proto_types::consumer_cache_stack_entry::Source::External(external)) => {
            format!("External cache · {}", external.url)
        }
        None => "Invalid cache source".to_string(),
    }
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
    fn external_cache_urls_reject_credentials_and_varying_suffixes() {
        assert!(validate_external_url("https://cache.example.test/nix").is_ok());
        assert!(validate_external_url("ftp://cache.example.test").is_err());
        assert!(validate_external_url("https://user@cache.example.test").is_err());
        assert!(validate_external_url("https://cache.example.test?q=one").is_err());
        assert!(validate_external_url("https://cache.example.test#part").is_err());
    }
}
