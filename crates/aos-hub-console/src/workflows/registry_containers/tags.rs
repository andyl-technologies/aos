//! Mutable tag pointers and append-only tag history.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::app::refresh;
use crate::components::{HashValue, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{
    container_tag_controls_visible, container_tag_is_manually_mutable, idempotency_key, PendingPlan,
};
use crate::transport::ApiClient;

use super::display_or;

/// Renders tag inventory, history, resolution, and reviewed manual mutation.
#[component]
pub(super) fn ContainerTags(
    client: ApiClient,
    registry: String,
    repository: String,
) -> impl IntoView {
    let can_publish = container_tag_controls_visible(|permission| client.allows(permission));
    let list_client = client.clone();
    let list_registry = registry.clone();
    let list_repository = repository.clone();
    let tags = LocalResource::new(move || {
        let client = list_client.clone();
        let registry = list_registry.clone();
        let repository = list_repository.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListContainerTagsResponse, _, _, _>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_TAGS_PATH,
                    move |page_token| aos_proto_types::ListContainerTagsRequest {
                        registry: registry.clone(),
                        repository: repository.clone(),
                        tag_prefix: String::new(),
                        ownership_kind: String::new(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.tags, response.next_page_token),
                )
                .await
        }
    });

    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Mutable pointers"</p><h2>"Tags & history"</h2><p>"Signed release and channel tags are immutable here; only manual pointers accept reviewed CAS mutations."</p></div></div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading tags…"</p> }>
                {move || Suspend::new(async move {
                    match tags.await.as_ref() {
                        Ok(values) if values.is_empty() => view! { <p class="muted">"No tags point into this repository."</p> }.into_any(),
                        Ok(values) => view! { <div class="compact-list">{values.iter().cloned().map(|tag| view! { <TagRow tag=tag/> }).collect_view()}</div> }.into_any(),
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })}
            </Suspense>
            <div class="subworkflow-grid">
                <TagHistory client=client.clone() registry=registry.clone() repository=repository.clone()/>
                <TagResolver client=client.clone() registry=registry.clone() repository=repository.clone()/>
            </div>
            {can_publish.then(|| view! { <ManualTagEditor client=client registry=registry repository=repository/> })}
        </section>
    }
}

#[component]
fn TagRow(tag: aos_proto_types::ContainerTag) -> impl IntoView {
    let mutable = container_tag_is_manually_mutable(&tag.ownership_kind);
    view! {
        <div class="compact-list-row"><div><strong>{tag.tag}</strong><span>{format!("{} · {}", tag.ownership_kind, display_or(&tag.media_type, "unknown media type"))}</span><small>{if mutable { "manual CAS eligible" } else { "signed read only" }}</small></div><HashValue value=tag.digest/><StatusBadge state=tag.ownership_kind.clone() positive=!mutable/></div>
    }
}

#[component]
fn TagHistory(client: ApiClient, registry: String, repository: String) -> impl IntoView {
    let tag = RwSignal::new(String::new());
    let entries = RwSignal::new(None::<Vec<aos_proto_types::ContainerTagHistoryEntry>>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let selected = tag.get_untracked().trim().to_string();
        if selected.is_empty() {
            error.set(Some("Tag name is required.".to_string()));
            return;
        }
        let client = client.clone();
        let registry = registry.clone();
        let repository = repository.clone();
        busy.set(true);
        error.set(None);
        entries.set(None);
        spawn_local(async move {
            match client
                .collect_pages::<_, aos_proto_types::ListContainerTagHistoryResponse, _, _, _>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_TAG_HISTORY_PATH,
                    move |page_token| aos_proto_types::ListContainerTagHistoryRequest {
                        registry: registry.clone(),
                        repository: repository.clone(),
                        tag: selected.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.entries, response.next_page_token),
                )
                .await
            {
                Ok(values) => entries.set(Some(values)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    view! {
        <div class="subworkflow">
            <h3>"Tag history"</h3>
            <form class="compact-form" on:submit=on_submit>
                <label><span>"Tag"</span><input required prop:value=move || tag.get() on:input=move |event| tag.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Load history"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || entries.get().map(|values| view! { <TagHistoryEntries entries=values/> })}
        </div>
    }
}

#[component]
fn TagHistoryEntries(entries: Vec<aos_proto_types::ContainerTagHistoryEntry>) -> impl IntoView {
    if entries.is_empty() {
        view! { <p class="muted">"No recorded revisions."</p> }.into_any()
    } else {
        view! {
            <div class="compact-list">
                {entries.into_iter().map(|entry| view! {
                    <div class="compact-list-row">
                        <div><strong>{entry.operation}</strong><span>{format!("{} · {}", entry.actor, entry.created_at)}</span></div>
                        <HashValue value=entry.digest/>
                    </div>
                }).collect_view()}
            </div>
        }.into_any()
    }
}

#[component]
fn TagResolver(client: ApiClient, registry: String, repository: String) -> impl IntoView {
    let tag = RwSignal::new(String::new());
    let os = RwSignal::new(String::new());
    let architecture = RwSignal::new(String::new());
    let variant = RwSignal::new(String::new());
    let os_version = RwSignal::new(String::new());
    let os_features = RwSignal::new(String::new());
    let resolved = RwSignal::new(None::<aos_proto_types::ContainerTagResolutionResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let client = client.clone();
        let request = aos_proto_types::ResolveContainerTagRequest {
            registry: registry.clone(),
            repository: repository.clone(),
            tag: tag.get_untracked().trim().to_string(),
            operating_system: os.get_untracked().trim().to_string(),
            architecture: architecture.get_untracked().trim().to_string(),
            variant: variant.get_untracked().trim().to_string(),
            os_version: os_version.get_untracked().trim().to_string(),
            os_features: ordered_os_features(&os_features.get_untracked()),
        };
        busy.set(true);
        error.set(None);
        resolved.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ContainerTagResolutionResponse>(
                    aos_proto_types::CONTAINER_SERVICE_RESOLVE_CONTAINER_TAG_PATH,
                    &request,
                )
                .await
            {
                Ok(value) => resolved.set(Some(value)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    view! {
        <div class="subworkflow">
            <h3>"Resolve tag"</h3>
            <form class="compact-form" on:submit=on_submit>
                <label><span>"Tag"</span><input required prop:value=move || tag.get() on:input=move |event| tag.set(event_target_value(&event))/></label>
                <label><span>"OS"</span><input placeholder="linux" prop:value=move || os.get() on:input=move |event| os.set(event_target_value(&event))/></label>
                <label><span>"Architecture"</span><input placeholder="amd64" prop:value=move || architecture.get() on:input=move |event| architecture.set(event_target_value(&event))/></label>
                <label><span>"Variant"</span><input prop:value=move || variant.get() on:input=move |event| variant.set(event_target_value(&event))/></label>
                <label><span>"OS version"</span><input prop:value=move || os_version.get() on:input=move |event| os_version.set(event_target_value(&event))/></label>
                <label><span>"Required OS features (ordered, one per line)"</span><textarea rows="3" prop:value=move || os_features.get() on:input=move |event| os_features.set(event_target_value(&event))></textarea></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Resolve"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || resolved.get().map(|value| {
                let tag = value.tag.unwrap_or_default();
                let manifest = value.manifest.unwrap_or_default();
                let platform = value.selected_platform.unwrap_or_default();
                let platform_label = format!(
                    "{}/{}{}",
                    platform.operating_system,
                    platform.architecture,
                    if platform.variant.is_empty() { String::new() } else { format!("/{}", platform.variant) },
                );
                let features = platform.os_features.join(", ");
                view! {
                    <div class="resource-identity">
                        <div><span>"Tag digest"</span><HashValue value=tag.digest/></div>
                        <div><span>"Manifest"</span><HashValue value=manifest.digest/></div>
                        <div><span>"Platform"</span><strong>{platform_label}</strong></div>
                        <div><span>"OS version"</span><strong>{display_or(&platform.os_version, "unspecified")}</strong></div>
                        <div><span>"OS features"</span><strong>{display_or(&features, "none")}</strong></div>
                    </div>
                }
            })}
        </div>
    }
}

fn ordered_os_features(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|feature| !feature.is_empty())
        .map(str::to_string)
        .collect()
}

#[component]
fn ManualTagEditor(client: ApiClient, registry: String, repository: String) -> impl IntoView {
    let tag = RwSignal::new(String::new());
    let digest = RwSignal::new(String::new());
    let expected_version = RwSignal::new(String::new());
    let expected_digest = RwSignal::new(String::new());
    let unset = RwSignal::new(false);
    let pending = RwSignal::new(None::<(PendingPlan, bool)>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let is_unset = unset.get_untracked();
        let key = idempotency_key(if is_unset {
            "container-tag-unset"
        } else {
            "container-tag-set"
        });
        let registry = registry.clone();
        let repository = repository.clone();
        let tag_name = tag.get_untracked().trim().to_string();
        let target = digest.get_untracked().trim().to_string();
        let version = expected_version.get_untracked().trim().to_string();
        let old_digest = expected_digest.get_untracked().trim().to_string();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let response = if is_unset {
                client
                    .call::<_, aos_proto_types::TopologyPlanResponse>(
                        aos_proto_types::CONTAINER_SERVICE_PLAN_UNSET_CONTAINER_TAG_PATH,
                        &aos_proto_types::PlanUnsetContainerTagRequest {
                            registry,
                            repository,
                            tag: tag_name,
                            expected_resource_version: version,
                            expected_digest: old_digest,
                            idempotency_key: key.clone(),
                        },
                    )
                    .await
            } else {
                client
                    .call::<_, aos_proto_types::TopologyPlanResponse>(
                        aos_proto_types::CONTAINER_SERVICE_PLAN_SET_CONTAINER_TAG_PATH,
                        &aos_proto_types::PlanSetContainerTagRequest {
                            registry,
                            repository,
                            tag: tag_name,
                            target_digest: target,
                            expected_resource_version: (!version.is_empty()).then_some(version),
                            expected_digest: (!old_digest.is_empty()).then_some(old_digest),
                            idempotency_key: key.clone(),
                        },
                    )
                    .await
            };
            match response
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, key))
            {
                Ok(reviewed) => pending.set(Some((reviewed, is_unset))),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some((reviewed, is_unset)) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = if is_unset {
                client
                    .call::<_, aos_proto_types::ContainerDeletionResponse>(
                        aos_proto_types::CONTAINER_SERVICE_UNSET_CONTAINER_TAG_PATH,
                        &reviewed.container_apply(),
                    )
                    .await
                    .map(|_| ())
            } else {
                client
                    .call::<_, aos_proto_types::ContainerTagResponse>(
                        aos_proto_types::CONTAINER_SERVICE_SET_CONTAINER_TAG_PATH,
                        &reviewed.container_apply(),
                    )
                    .await
                    .map(|_| ())
            };
            match result {
                Ok(()) => refresh(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    view! {
        <div class="subworkflow"><h3>"Manual tag mutation"</h3><p>"Use both expected fields to update an existing pointer. Leave them empty to require a new tag."</p><form class="editor-form" on:submit=on_plan><label><span>"Tag"</span><input required prop:value=move || tag.get() on:input=move |event| tag.set(event_target_value(&event))/></label><label><span>"Target digest"</span><input required=move || !unset.get() disabled=move || unset.get() placeholder="sha256:…" prop:value=move || digest.get() on:input=move |event| digest.set(event_target_value(&event))/></label><label><span>"Expected version"</span><input prop:value=move || expected_version.get() on:input=move |event| expected_version.set(event_target_value(&event))/></label><label><span>"Expected digest"</span><input placeholder="sha256:…" prop:value=move || expected_digest.get() on:input=move |event| expected_digest.set(event_target_value(&event))/></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || unset.get() on:change=move |event| unset.set(event_target_checked(&event))/><span>"Unset this manual tag"</span></label><div class="form-actions"><button class=move || if unset.get() { "danger-button" } else { "button" } type="submit" disabled=move || busy.get()>"Review tag change"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|(reviewed, _)| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</div>
    }
}
