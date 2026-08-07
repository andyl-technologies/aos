//! Placement-aware registry publication workflows.
//!
//! Producers begin from one exact manifest, upload immutable bytes before
//! mutable pointers, and commit only after every required placement verifies
//! every declared object. Failed sessions can be inspected and aborted without
//! exposing a slug-based storage bypass.

use leptos::ev::{Event, SubmitEvent};
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, StatusBadge};
use crate::transport::ApiClient;

/// Renders registry publication begin, resume, upload, commit, and abort flows.
#[component]
pub(super) fn RegistryPublicationWorkflow(client: ApiClient, registry_id: String) -> impl IntoView {
    let publication = RwSignal::new(None::<aos_proto_types::RegistryPublication>);
    view! {
        <div class="workflow-stack">
            <PublicationBegin
                client=client.clone()
                registry_id=registry_id
                publication=publication
            />
            <PublicationLookup client=client.clone() publication=publication/>
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
                    <h2>"Begin publication"</h2>
                    <p>"The JSON contract is identical to `aos hub publish begin`. The registry is bound to this page and cannot be redirected by pasted JSON."</p>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label>
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
fn PublicationLookup(
    client: ApiClient,
    publication: RwSignal<Option<aos_proto_types::RegistryPublication>>,
) -> impl IntoView {
    let publication_id = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let id = publication_id.get_untracked().trim().to_string();
        if id.is_empty() {
            error.set(Some("Publication ID is required".to_string()));
            return;
        }
        let client = client.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RegistryPublication>(
                    aos_proto_types::PUBLISH_SERVICE_GET_REGISTRY_PUBLICATION_PATH,
                    &aos_proto_types::GetRegistryPublicationRequest { publication_id: id },
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
            <div class="section-heading"><div><p class="section-kicker">"Resume exact session"</p><h2>"Load publication"</h2></div></div>
            <form class="editor-form" on:submit=on_submit>
                <label><span>"Publication ID"</span><input required prop:value=move || publication_id.get() on:input=move |event| publication_id.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Load publication"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
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
                <StatusBadge state=value.state.clone() positive=value.state == "committed"/>
            </div>
            <div class="resource-identity">
                <div><span>"Manifest digest"</span><code>{value.manifest_digest.clone()}</code></div>
                <div><span>"Refs digest"</span><code>{value.refs_digest.clone()}</code></div>
                <div><span>"Default commit"</span><code>{display_or(&value.default_commit, "none")}</code></div>
                <div><span>"Parent publication"</span><code>{display_or(&value.parent_publication_id, "none")}</code></div>
            </div>
            <h3>"Required placements"</h3>
            <div class="compact-list">
                {value.placements.iter().cloned().map(|placement| view! {
                    <div class="compact-list-row"><strong>{placement.name}</strong><StatusBadge state=placement.state positive=!placement.required || value.state == "committed"/></div>
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
                <div><strong>{object.path}</strong><code>{object.sha256}</code></div>
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
            <button class="button" type="button" disabled=move || busy.get() on:click=on_commit>"Commit verified publication"</button>
            <button class="danger-button" type="button" disabled=move || busy.get() on:click=on_abort>"Abort publication"</button>
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
