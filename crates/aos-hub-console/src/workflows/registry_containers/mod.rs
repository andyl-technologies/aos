//! OCI repository administration and signed-image inspection.
//!
//! The workflow keeps registry metadata, mutable manual tags, immutable OCI
//! graphs, verified publication provenance, and retention policy visibly
//! separate. Every request crosses the authenticated Connect transport; the
//! browser never receives a server-rendered private repository model.

mod gc;
mod inspection;
mod publications;
mod retention;
mod tags;

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local_scoped_with_cancellation as spawn_local;

use crate::app::refresh;
use crate::components::{CopyableCommand, EmptyState, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

use self::gc::ContainerGc;
use self::inspection::ContainerGraphInspector;
use self::publications::ContainerPublications;
use self::retention::ContainerRetention;
use self::tags::ContainerTags;

/// Renders repository inventory, selected-repository detail, and retention.
#[component]
pub(super) fn RegistryContainers(client: ApiClient, registry_id: String) -> impl IntoView {
    let prefix = RwSignal::new(String::new());
    let lifecycle = RwSignal::new(String::new());
    let selected = RwSignal::new(None::<String>);
    let list_client = client.clone();
    let list_registry = registry_id.clone();
    let repositories = LocalResource::new(move || {
        let client = list_client.clone();
        let registry = list_registry.clone();
        let repository_prefix = prefix.get().trim().to_string();
        let lifecycle_state = lifecycle.get();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListContainerRepositoriesResponse, _, _, _>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_REPOSITORIES_PATH,
                    move |page_token| aos_proto_types::ListContainerRepositoriesRequest {
                        registry: registry.clone(),
                        repository_prefix: repository_prefix.clone(),
                        lifecycle_state: lifecycle_state.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.repositories, response.next_page_token),
                )
                .await
        }
    });
    let workspace_client = client.clone();
    let workspace_registry = registry_id.clone();
    let gc_requested = RwSignal::new(false);

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"OCI Distribution repositories"</p>
                        <h2>"Containers"</h2>
                        <p>"Inspect signed AOS images, exact manifests, shared layers, evidence, and mutable manual tags."</p>
                    </div>
                </div>
                <form class="compact-form" on:submit=move |event: SubmitEvent| event.prevent_default()>
                    <label><span>"Repository prefix"</span><input placeholder="base" prop:value=move || prefix.get() on:input=move |event| prefix.set(event_target_value(&event))/></label>
                    <label><span>"Lifecycle"</span><select prop:value=move || lifecycle.get() on:change=move |event| lifecycle.set(event_target_value(&event))><option value="">"Any state"</option><option value="active">"Active"</option><option value="deleting">"Deleting"</option></select></label>
                </form>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading container repositories…"</p> }>
                    {move || Suspend::new(async move {
                        match repositories.await.as_ref() {
                            Ok(values) if values.is_empty() => view! {
                                <EmptyState title="No container repositories".to_string() detail="Push an OCI image or create a repository through the reviewed API.".to_string() action_label=None action=None/>
                            }.into_any(),
                            Ok(values) => view! {
                                <div class="resource-grid">
                                    {values.iter().cloned().map(|repository| {
                                        let name = repository.repository.clone();
                                        view! {
                                            <button class="resource-card container-repository-card" type="button" on:click=move |_| selected.set(Some(name.clone()))>
                                                <div><span class="resource-kind">{repository.visibility}</span><h3>{repository.repository}</h3><p>{display_or(&repository.description, "No description")}</p><p class="resource-metric">{format!("{} tags · {} manifests · {}", repository.tag_count, repository.manifest_count, format_bytes(repository.unique_byte_size))}</p></div>
                                                <StatusBadge state=repository.lifecycle_state.clone() positive=repository.lifecycle_state == "active"/>
                                            </button>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any(),
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })}
                </Suspense>
            </section>
            {move || selected.get().map(|repository| view! { <RepositoryWorkspace client=workspace_client.clone() registry=workspace_registry.clone() repository=repository/> })}
            <ContainerRetention client=client.clone() registry=registry_id.clone()/>
            <details class="panel advanced-controls" on:toggle=move |_| gc_requested.set(true)>
                <summary>"Garbage collection & provider reconciliation"</summary>
                {move || gc_requested.get().then(|| view! {
                    <ContainerGc client=client.clone() registry=registry_id.clone()/>
                })}
            </details>
        </div>
    }
}

#[component]
fn RepositoryWorkspace(client: ApiClient, registry: String, repository: String) -> impl IntoView {
    let read_client = client.clone();
    let read_registry = registry.clone();
    let read_repository = repository.clone();
    let detail = LocalResource::new(move || {
        let client = read_client.clone();
        let registry = read_registry.clone();
        let repository = read_repository.clone();
        async move {
            client
                .call::<_, aos_proto_types::ContainerRepositoryResponse>(
                    aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_REPOSITORY_PATH,
                    &aos_proto_types::GetContainerRepositoryRequest {
                        registry,
                        repository,
                    },
                )
                .await
        }
    });

    view! {
        <Suspense fallback=move || view! { <section class="panel"><p class="loading-row">"Loading repository detail…"</p></section> }>
            {move || {
                let client = client.clone();
                let registry = registry.clone();
                let repository = repository.clone();
                Suspend::new(async move {
                    match detail.await.as_ref() {
                        Ok(response) => match response.repository.clone() {
                            Some(value) => view! {
                                <div class="workflow-stack container-workspace">
                                    <RepositoryDetail client=client.clone() repository=value/>
                                    <ContainerTags client=client.clone() registry=registry.clone() repository=repository.clone()/>
                                    <ContainerGraphInspector client=client.clone() registry=registry.clone() repository=repository.clone()/>
                                    <ContainerPublications client=client registry=registry repository=repository/>
                                </div>
                            }.into_any(),
                            None => view! { <InlineError detail="The Hub omitted the repository detail.".to_string()/> }.into_any(),
                        },
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn RepositoryDetail(
    client: ApiClient,
    repository: aos_proto_types::ContainerRepository,
) -> impl IntoView {
    let description = RwSignal::new(repository.description.clone());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let registry = repository.registry.clone();
    let name = repository.repository.clone();
    let version = repository.resource_version.clone();
    let can_manage = client.allows("registry.configure");
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let key = idempotency_key("container-repository-description");
        let request = aos_proto_types::PlanUpdateContainerRepositoryRequest {
            registry: registry.clone(),
            repository: name.clone(),
            description: description.get_untracked().trim().to_string(),
            update_mask: vec!["description".to_string()],
            expected_resource_version: version.clone(),
            idempotency_key: key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::CONTAINER_SERVICE_PLAN_UPDATE_CONTAINER_REPOSITORY_PATH,
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
                .call::<_, aos_proto_types::ContainerRepositoryResponse>(
                    aos_proto_types::CONTAINER_SERVICE_UPDATE_CONTAINER_REPOSITORY_PATH,
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
        <section class="panel editor-panel">
            <div class="section-heading"><div><p class="section-kicker">"Selected repository"</p><h2>{repository.repository}</h2></div><StatusBadge state=repository.lifecycle_state.clone() positive=repository.lifecycle_state == "active"/></div>
            <div class="resource-identity"><div><span>"Registry"</span><code>{repository.registry}</code></div><div><span>"Visibility"</span><strong>{repository.visibility}</strong></div><div><span>"Tags"</span><strong>{repository.tag_count}</strong></div><div><span>"Manifests"</span><strong>{repository.manifest_count}</strong></div><div><span>"Compressed"</span><strong>{format_bytes(repository.compressed_byte_size)}</strong></div><div><span>"Unique bytes"</span><strong>{format_bytes(repository.unique_byte_size)}</strong></div><div><span>"Version"</span><code>{repository.resource_version}</code></div></div>
            <RepositoryPullCommands distribution_reference=repository.distribution_reference/>
            {can_manage.then(|| view! {
                <form class="editor-form" on:submit=on_plan><label><span>"Description"</span><textarea maxlength="512" rows="3" prop:value=move || description.get() on:input=move |event| description.set(event_target_value(&event))></textarea></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review description"</button></div></form>
            })}
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn RepositoryPullCommands(distribution_reference: String) -> impl IntoView {
    let commands = aos_hub_console_contract::container_pull_commands(&distribution_reference);
    (!commands.is_empty()).then(|| {
        view! {
            <div class="subworkflow container-pull-commands">
                <h3>"Pull this repository"</h3>
                <p class="muted">"The Hub exposes these commands only while its exact OCI Distribution route is ready."</p>
                {commands
                    .into_iter()
                    .map(|command| view! {
                        <CopyableCommand client=command.client command=command.command/>
                    })
                    .collect_view()}
            </div>
        }
    })
}

pub(super) fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

pub(super) fn format_bytes(value: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if value >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", value as f64 / GIB)
    } else if value >= 1024 * 1024 {
        format!("{:.1} MiB", value as f64 / MIB)
    } else {
        format!("{value} bytes")
    }
}
