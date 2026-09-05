//! Registry-owned signed consumer-cache stack workflows.
//!
//! The registry owns ordering and signs the resulting consumer configuration.
//! Stack entries may reference shared managed caches or external HTTP origins.
//! Every mutation carries the exact stack version through immutable plan/apply.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{HashValue, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

/// Renders a registry's ordered consumer-cache stack and validation result.
#[component]
pub(super) fn RegistryCacheStack(client: ApiClient, registry_id: String) -> impl IntoView {
    let stack = stack_resource(client.clone(), registry_id.clone());
    let validation = validation_resource(client.clone(), registry_id.clone());
    let caches = cache_resource(client.clone());
    let create_href = registry_id
        .split_once('/')
        .map(|(organization, _)| format!("/-/org/{organization}/caches/new"));
    let view_client = client;
    let view_registry = registry_id;

    view! {
        <div class="workflow-stack">
            <ManagedCaches caches=caches create_href=create_href/>
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"Signed consumer configuration"</p>
                        <h2>"Client cache sources"</h2>
                        <p>
                            "Clients try these signed sources in order. Adding a source references an existing cache; it does not create storage, copy packages, or retain them."
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
                                    caches,
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

type CacheInventory =
    LocalResource<Result<Vec<aos_proto_types::BinaryCache>, crate::transport::TransportError>>;

fn cache_resource(client: ApiClient) -> CacheInventory {
    LocalResource::new(move || {
        let client = client.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListBinaryCachesResponse, _, _, _>(
                    aos_proto_types::BINARY_CACHE_SERVICE_LIST_BINARY_CACHES_PATH,
                    |page_token| aos_proto_types::ListBinaryCachesRequest {
                        owner_scope_key: String::new(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.caches, response.next_page_token),
                )
                .await
        }
    })
}

#[component]
fn ManagedCaches(caches: CacheInventory, create_href: Option<String>) -> impl IntoView {
    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div>
                <p class="section-kicker">"Cache resources"</p><h2>"Managed binary caches"</h2>
                <p>"Configure each cache's storage, delivery, signing, retention, and population in its own settings. Caches can be shared by multiple registries."</p>
            </div></div>
            <div class="form-actions">
                {create_href.map(|href| view! { <a class="button" href=href>"Create binary cache in this organization"</a> })}
                <a class="secondary-button" href="/-/caches">"Browse all caches"</a>
            </div>
            <p class="muted">"These are caches you can read, including shared caches. Configuring a cache requires permission in its own scope. A registry cache-stack entry is a reference, not a separate cache resource."</p>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading managed caches…"</p> }>
                {move || Suspend::new(async move {
                    match caches.await.as_ref() {
                        Ok(caches) if caches.is_empty() => view! { <p class="muted">"No managed caches are available. Create one in an organization you manage, or ask a cache owner for access. External sources can be added below."</p> }.into_any(),
                        Ok(caches) => view! { <div class="binding-list">{caches.iter().map(|cache| {
                            let href = cache_href(&cache.slug);
                            view! { <article class="revision-card">
                                <div class="compact-list-row"><div><strong>{cache.name.clone()}</strong><code>{cache.slug.clone()}</code><span>{format!("{} objects · {} storage placements", cache.object_count, cache.placement_count)}</span></div></div>
                                <div class="form-actions">
                                    <a class="table-action" href=href.clone()>"Cache settings"</a>
                                    <a class="table-action" href=format!("{href}/placements")>"Storage"</a>
                                    <a class="table-action" href=format!("{href}/delivery")>"Delivery"</a>
                                    <a class="table-action" href=format!("{href}/retention")>"Retention"</a>
                                </div>
                            </article> }
                        }).collect_view()}</div> }.into_any(),
                        Err(failure) => view! { <InlineError detail=format!("Could not load managed caches: {failure}")/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn ManagedCacheSelect(caches: CacheInventory, selected: RwSignal<String>) -> impl IntoView {
    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Loading cache choices…"</p> }>
            {move || Suspend::new(async move {
                match caches.await.as_ref() {
                    Ok(caches) => view! { <label><span>"Managed cache"</span>
                        <select required prop:value=move || selected.get() on:change=move |event| selected.set(event_target_value(&event))>
                            <option value="">"Select a cache"</option>
                            {caches.iter().map(|cache| view! { <option value=cache.slug.clone()>{format!("{} ({})", cache.name, cache.slug)}</option> }).collect_view()}
                        </select>
                        <small>"The cache needs a ready canonical Nix cache delivery route before it can be added. Configure Delivery in its settings above."</small>
                    </label> }.into_any(),
                    Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                }
            })}
        </Suspense>
    }
}

#[component]
fn EntrySelect(
    selected: RwSignal<String>,
    entries: Vec<aos_proto_types::ConsumerCacheStackEntry>,
    empty_label: &'static str,
) -> impl IntoView {
    view! { <select prop:value=move || selected.get() on:change=move |event| selected.set(event_target_value(&event))>
        <option value="">{empty_label}</option>
        {entries.into_iter().map(|entry| { let label = source_name(&entry); view! { <option value=entry.entry_id>{label}</option> } }).collect_view()}
    </select> }
}

#[component]
fn ChangeResult(completed: RwSignal<Option<String>>, href: String) -> impl IntoView {
    view! { {move || completed.get().map(|message| view! { <div role="status"><p>{message}</p><a href=href.clone()>"Review and merge change requests"</a></div> })} }
}

fn cache_href(slug: &str) -> String {
    match slug.split_once('/') {
        Some((organization, cache)) => format!("/-/org/{organization}/caches/{cache}"),
        None => format!("/-/caches/{slug}"),
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
    caches: CacheInventory,
) -> AnyView {
    let can_manage = client.allows("registry.configure");
    let entries = stack.entries.clone();
    let changes_href = format!("/{registry_id}/-/settings/change-requests");
    let version = stack.resource_version.clone();
    view! {
        <div class="resource-identity">
            <div><span>"Indexed commit"</span>{if stack.indexed_commit.is_empty() { view! { <span>"not indexed"</span> }.into_any() } else { view! { <HashValue value=stack.indexed_commit/> }.into_any() }}</div>
            <div><span>"Version"</span><code>{display_or(&version, "initial")}</code></div>
        </div>
        <p>"Changes create a signed change request. Merge it and index the registry to update this published list. "<a href=changes_href>"View change requests"</a></p>
        {entries.is_empty().then(|| view! { <p class="muted">"No cache sources are published. Create or configure a managed cache above, then add it here; you can also use an external cache URL."</p> })}
        {(!can_manage).then(|| view! { <p class="muted">"Registry configuration permission is required to change cache sources."</p> })}
        <div class="binding-list">
            {stack
                .entries
                .into_iter()
                .map(|entry| view! {
                    <CacheStackEntry
                        client=client.clone()
                        registry_id=registry_id.clone()
                        version=version.clone()
                        choices=entries.clone()
                        can_manage=can_manage
                        entry=entry
                    />
                })
                .collect_view()}
        </div>
        {can_manage.then(|| view! { <CacheStackAdd client=client registry_id=registry_id version=version caches=caches entries=entries/> })}
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
                    <p class="section-kicker">"Published source checks"</p>
                    <h2>"Source validation"</h2>
                    <p>"Checks configured sources and managed cache routes. This does not test downloading packages from every source."</p>
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
    choices: Vec<aos_proto_types::ConsumerCacheStackEntry>,
    can_manage: bool,
) -> impl IntoView {
    let before = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let entry_id = entry.entry_id.clone();

    let changes_href = format!("/{registry_id}/-/settings/change-requests");
    let completed = RwSignal::new(None::<String>);
    let move_choices = choices
        .into_iter()
        .filter(|choice| choice.entry_id != entry.entry_id)
        .collect::<Vec<_>>();
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
    let apply = apply_callback(client, pending, error, busy, completed);
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
                    disabled=move || busy.get() || !can_manage
                    on:click=move |_| on_action.run("remove")
                >
                    "Review removal"
                </button>
            </div>
            <div class="form-actions">
                <label><span>"Move before"</span><EntrySelect selected=before entries=move_choices empty_label="Last source"/></label>
                <button
                    class="table-action"
                    type="button"
                    disabled=move || busy.get() || !can_manage
                    on:click=move |_| move_action.run("move")
                >
                    "Review move"
                </button>
            </div>
            <ChangeResult completed=completed href=changes_href/>
            <PlanReview pending=pending error=error busy=busy on_apply=apply/>
        </article>
    }
}

#[component]
fn CacheStackAdd(
    client: ApiClient,
    registry_id: String,
    version: String,
    caches: CacheInventory,
    entries: Vec<aos_proto_types::ConsumerCacheStackEntry>,
) -> impl IntoView {
    let source_kind = RwSignal::new("managed".to_string());
    let managed_value = RwSignal::new(String::new());
    let external_value = RwSignal::new(String::new());
    let completed = RwSignal::new(None::<String>);
    let changes_href = format!("/{registry_id}/-/settings/change-requests");
    let before = RwSignal::new(String::new());
    let mirror_with = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let value = if source_kind.get_untracked() == "managed" {
            managed_value.get_untracked()
        } else {
            external_value.get_untracked()
        };
        let source = match cache_source(&source_kind.get_untracked(), &value) {
            Ok(source) => source,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let entry_id = idempotency_key("cache-stack-entry");
        let change = aos_proto_types::ConsumerCacheChange {
            operation: "add".to_string(),
            entry_id: String::new(),
            desired: Some(aos_proto_types::ConsumerCacheStackEntry {
                entry_id,
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
    let apply = apply_callback(client, pending, error, busy, completed);

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
                {move || if source_kind.get() == "managed" {
                    view! { <ManagedCacheSelect caches=caches selected=managed_value/> }.into_any()
                } else {
                    view! { <label><span>"External HTTP(S) URL"</span><input required type="url" placeholder="https://cache.example.com" prop:value=move || external_value.get() on:input=move |event| external_value.set(event_target_value(&event))/></label> }.into_any()
                }}
                <label><span>"Insert before"</span><EntrySelect selected=before entries=entries.clone() empty_label="Last source"/></label>
                <label><span>"Mirror an existing source"</span><EntrySelect selected=mirror_with entries=entries empty_label="Independent source"/></label>
                <p class="muted">"Use a mirror only when both sources serve the same content."</p>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    "Review stack change"
                </button>
            </form>
            <ChangeResult completed=completed href=changes_href/>
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
        return Err("Select a managed cache or enter an external URL".to_string());
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
    completed: RwSignal<Option<String>>,
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
                Ok(response) => {
                    pending.set(None);
                    completed.set(Some(format!("Change request {} created ({}). The published sources are unchanged until merge and indexing.", response.change_id, response.state)));
                }
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
