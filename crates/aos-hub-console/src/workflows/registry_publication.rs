//! Placement-aware registry publication workflows.
//!
//! Producers begin from one exact manifest, upload immutable bytes before
//! mutable pointers, and commit only after every required placement verifies
//! every declared object. Failed sessions can be inspected and aborted without
//! exposing a slug-based storage bypass.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::{Event, SubmitEvent};
use leptos::prelude::*;

use crate::components::{HashValue, HelpTooltip, InlineError, StatusBadge};
use crate::transport::ApiClient;

/// Renders registry publication begin, resume, upload, commit, and abort flows.
#[component]
pub(super) fn RegistryPublicationWorkflow(client: ApiClient, registry_id: String) -> impl IntoView {
    let publication = RwSignal::new(None::<aos_proto_types::RegistryPublication>);
    let can_publish = client.allows("publish");
    view! {
        <div class="workflow-stack">
            <PublicationHistory
                client=client.clone()
                registry_id=registry_id.clone()
                publication=publication
            />
            {can_publish.then(|| view! {
                <details class="panel advanced-controls">
                    <summary>"Advanced: begin a publication from a manifest"</summary>
                    <p class="muted">"Publish signed releases with apr. Use this form to inspect or recover a prepared publication manifest."</p>
                    <PublicationBegin client=client.clone() registry_id=registry_id publication=publication/>
                </details>
            })}
            {move || publication.get().map(|value| view! {
                <PublicationSession client=client.clone() publication=publication value=value/>
            })}
        </div>
    }
}

#[component]
fn PublicationBegin(
    client: ApiClient,
    registry_id: String,
    publication: RwSignal<Option<aos_proto_types::RegistryPublication>>,
) -> impl IntoView {
    let manifest = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let mut request = match serde_json::from_str::<
            aos_proto_types::BeginRegistryPublicationRequest,
        >(&manifest.get_untracked())
        {
            Ok(request) => request,
            Err(failure) => {
                error.set(Some(format!(
                    "Invalid publication manifest JSON: {failure}"
                )));
                return;
            }
        };
        if !request.registry.is_empty() && request.registry != registry_id {
            error.set(Some(
                "Manifest registry does not match this registry".to_string(),
            ));
            return;
        }
        request.registry = registry_id.clone();
        let client = client.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RegistryPublication>(
                    aos_proto_types::PUBLISH_SERVICE_BEGIN_REGISTRY_PUBLICATION_PATH,
                    &request,
                )
                .await
            {
                Ok(response) => publication.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Frozen producer manifest"</p>
                    <h2>"Begin publication"<HelpTooltip term="Begin publication" summary="Use the prepared signed publication manifest for this registry. The registry cannot be changed by the pasted manifest."/></h2>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label class="full-field">
                    <span>"Publication manifest JSON"</span>
                    <textarea required rows="14" prop:value=move || manifest.get() on:input=move |event| manifest.set(event_target_value(&event))></textarea>
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    {move || if busy.get() { "Beginning…" } else { "Begin or resume publication" }}
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        </section>
    }
}

#[component]
fn PublicationHistory(
    client: ApiClient,
    registry_id: String,
    publication: RwSignal<Option<aos_proto_types::RegistryPublication>>,
) -> impl IntoView {
    let history = LocalResource::new(move || {
        let client = client.clone();
        let registry = registry_id.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListRegistryPublicationsResponse, _, _, _>(
                    aos_proto_types::PUBLISH_SERVICE_LIST_REGISTRY_PUBLICATIONS_PATH,
                    move |page_token| aos_proto_types::ListRegistryPublicationsRequest {
                        registry: registry.clone(),
                        state: String::new(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.publications, response.next_page_token),
                )
                .await
                .map_err(|failure| failure.to_string())
        }
    });
    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Registry publishing"</p>
                    <h2>"Publish history"<HelpTooltip term="Publish history" summary="Track publication progress, inspect failures, and resume interrupted uploads."/></h2>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading publication history…"</p> }>
                {move || Suspend::new(async move {
                    match history.await.as_ref() {
                        Ok(records) if records.is_empty() => view! {
                            <p class="muted">"No publication sessions have been created."</p>
                        }.into_any(),
                        Ok(records) => view! {
                            <div class="binding-list">
                                {records.iter().cloned().map(|record| {
                                    let selected = record.clone();
                                    view! {
                                        <article class="revision-card">
                                            <div class="compact-list-row">
                                                <div>
                                                    <strong>{record.generation}</strong>
                                                    <code>{record.publication_id}</code>
                                                </div>
                                                <StatusBadge state=record.state.clone() positive=record.state == "ready"/>
                                            </div>
                                            <div class="resource-identity">
                                                <div><span>"Ordinal"</span><strong>{record.ordinal}</strong></div>
                                                <div><span>"Created"</span><strong>{record.created_at}</strong></div>
                                                <div><span>"Objects"</span><strong>{record.objects.len()}</strong></div>
                                                <div><span>"Placements"</span><strong>{record.placements.len()}</strong></div>
                                            </div>
                                            <button class="secondary-button" type="button" on:click=move |_| publication.set(Some(selected.clone()))>
                                                "Inspect publication"
                                            </button>
                                        </article>
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any(),
                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn PublicationSession(
    client: ApiClient,
    publication: RwSignal<Option<aos_proto_types::RegistryPublication>>,
    value: aos_proto_types::RegistryPublication,
) -> impl IntoView {
    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div><p class="section-kicker">"Placement-aware transaction"</p><h2>{value.generation.clone()}</h2><code>{value.publication_id.clone()}</code></div>
                <StatusBadge state=value.state.clone() positive=value.state == "ready"/>
            </div>
            <div class="resource-identity">
                <div><span>"Manifest digest"</span><HashValue value=value.manifest_digest.clone()/></div>
                <div><span>"Refs digest"</span><HashValue value=value.refs_digest.clone()/></div>
                <div><span>"Default commit"</span>{if value.default_commit.is_empty() { view! { <span>"none"</span> }.into_any() } else { view! { <HashValue value=value.default_commit.clone()/> }.into_any() }}</div>
                <div><span>"Parent publication"</span><code>{display_or(&value.parent_publication_id, "none")}</code></div>
            </div>
            <h3>"Required placements"</h3>
            <div class="compact-list">
                {value.placements.iter().cloned().map(|placement| view! {
                    <div class="compact-list-row"><strong>{placement.name}</strong><StatusBadge state=placement.state.clone() positive=!placement.required || placement.state == "ready"/></div>
                }).collect_view()}
            </div>
            <h3>"Declared objects"</h3>
            <p>"Choose the exact file for each path. The Hub verifies declared size and SHA-256 on every required placement. Mutable pointers remain blocked until immutable objects complete."</p>
            <div class="binding-list">
                {value.objects.iter().cloned().map(|object| view! {
                    <PublicationObjectUpload client=client.clone() object=object/>
                }).collect_view()}
            </div>
            <PublicationLifecycle client=client publication=publication value=value/>
        </section>
    }
}

#[component]
fn PublicationObjectUpload(
    client: ApiClient,
    object: aos_proto_types::RegistryPublicationObject,
) -> impl IntoView {
    let status = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let expected_size = object.byte_size;
    let upload_url = object.upload_url.clone();
    let upload_available = !upload_url.is_empty();
    let on_file = move |event: Event| {
        let input = event_target::<leptos::web_sys::HtmlInputElement>(&event);
        let Some(file) = input.files().and_then(|files| files.get(0)) else {
            return;
        };
        if file.size() != expected_size as f64 {
            error.set(Some(format!(
                "Selected file has {} bytes; the manifest requires {expected_size}",
                file.size()
            )));
            return;
        }
        let client = client.clone();
        let upload_url = upload_url.clone();
        error.set(None);
        status.set(None);
        busy.set(true);
        spawn_local(async move {
            match client.put_publication_object(&upload_url, &file).await {
                Ok(()) => status.set(Some("Verified on every required placement".to_string())),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{object.path}</strong><HashValue value=object.sha256/></div>
                <StatusBadge state=object.kind.clone() positive=object.kind == "immutable"/>
            </div>
            <div class="resource-identity">
                <div><span>"Bytes"</span><strong>{object.byte_size}</strong></div>
                <div><span>"Media type"</span><code>{object.media_type}</code></div>
                <div><span>"Object ID"</span><strong>{object.object_id}</strong></div>
            </div>
            <input type="file" disabled=!upload_available || busy.get() on:change=on_file/>
            {(object.kind == "mutable_pointer").then(|| view! { <p class="muted">"Upload this only after every immutable object. The Hub rejects out-of-order pointer bytes."</p> })}
            {move || status.get().map(|value| view! { <StatusBadge state=value positive=true/> })}
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        </article>
    }
}

#[component]
fn PublicationLifecycle(
    client: ApiClient,
    publication: RwSignal<Option<aos_proto_types::RegistryPublication>>,
    value: aos_proto_types::RegistryPublication,
) -> impl IntoView {
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let can_commit = value.state == "writing_pointers";
    let can_abort = matches!(value.state.as_str(), "preparing" | "writing_pointers");
    let commit_client = client.clone();
    let commit_id = value.publication_id.clone();
    let on_commit = move |_| {
        let client = commit_client.clone();
        let publication_id = commit_id.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RegistryPublication>(
                    aos_proto_types::PUBLISH_SERVICE_COMMIT_REGISTRY_PUBLICATION_PATH,
                    &aos_proto_types::CommitRegistryPublicationRequest { publication_id },
                )
                .await
            {
                Ok(response) => publication.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    let abort_id = value.publication_id;
    let on_abort = move |_| {
        let client = client.clone();
        let publication_id = abort_id.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RegistryPublication>(
                    aos_proto_types::PUBLISH_SERVICE_ABORT_REGISTRY_PUBLICATION_PATH,
                    &aos_proto_types::AbortRegistryPublicationRequest { publication_id },
                )
                .await
            {
                Ok(response) => publication.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    view! {
        <div class="form-actions">
            <button class="button" type="button" disabled=move || busy.get() || !can_commit on:click=on_commit>"Commit verified publication"</button>
            <button class="danger-button" type="button" disabled=move || busy.get() || !can_abort on:click=on_abort>"Abort publication"</button>
        </div>
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
    }
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}
