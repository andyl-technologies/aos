//! Cache object search, exact metadata, and closure inspection.
//!
//! Logical object metadata is distinct from physical placement inventory. This
//! workflow shows NAR identity and recursively resolved closure presence without
//! implying that one successful placement represents every route.

use leptos::ev::{Event, SubmitEvent};
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HashValue, InlineError, StatusBadge};
use crate::transport::ApiClient;

/// Renders cache search and exact object/closure inspection.
#[component]
pub(super) fn CacheObjects(client: ApiClient, cache_id: String) -> impl IntoView {
    let can_upload = client.allows("registry.configure");
    view! {
        <div class="workflow-stack">
            <ObjectSearch client=client.clone() cache_id=cache_id.clone()/>
            <ObjectInspector client=client.clone() cache_id=cache_id.clone()/>
            {can_upload.then(|| view! {
                <details class="panel editor-panel">
                    <summary>
                        <div>
                            <span class="resource-kind">"Advanced producer operation"</span>
                            <strong>"Upload a cache object"</strong>
                        </div>
                    </summary>
                    <p>
                        "Use this only when producing an exact cache path. Search and inspect objects above before writing new content."
                    </p>
                    <ObjectUpload client=client.clone() cache_id=cache_id.clone()/>
                </details>
            })}
        </div>
    }
}

#[component]
fn ObjectUpload(client: ApiClient, cache_id: String) -> impl IntoView {
    let path = RwSignal::new(String::new());
    let status = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_file = move |event: Event| {
        let input = event_target::<leptos::web_sys::HtmlInputElement>(&event);
        let Some(file) = input.files().and_then(|files| files.get(0)) else {
            return;
        };
        let object_path = path.get_untracked().trim().to_string();
        if object_path.is_empty() {
            error.set(Some("Cache-relative object path is required".to_string()));
            return;
        }
        let client = client.clone();
        let cache_id = cache_id.clone();
        status.set(None);
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match upload_cache_file(client, cache_id, object_path, file).await {
                Ok(detail) => status.set(Some(detail)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="editor-form">
                <label><span>"Cache-relative path"</span><input required placeholder="nar/<hash>.nar.zst or <store-hash>.narinfo" prop:value=move || path.get() on:input=move |event| path.set(event_target_value(&event))/></label>
                <label><span>"Exact object bytes"</span><input type="file" disabled=move || busy.get() on:change=on_file/></label>
        </div>
        <p class="field-note">"Choosing a file starts the authenticated upload. Large objects use multipart storage automatically."</p>
        {move || status.get().map(|value| view! { <StatusBadge state=value positive=true/> })}
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
    }
}

async fn upload_cache_file(
    client: ApiClient,
    cache_id: String,
    path: String,
    file: leptos::web_sys::File,
) -> Result<String, String> {
    let byte_size = file.size() as u64;
    let admission = client
        .call::<_, aos_proto_types::CreateCacheObjectUploadsResponse>(
            aos_proto_types::BINARY_CACHE_SERVICE_CREATE_CACHE_OBJECT_UPLOADS_PATH,
            &aos_proto_types::CreateCacheObjectUploadsRequest {
                cache_id: cache_id.clone(),
                path: path.clone(),
                paths: Vec::new(),
                size: byte_size,
                sizes: Vec::new(),
                delivery_url: String::new(),
            },
        )
        .await
        .map_err(|failure| failure.to_string())?;
    if !admission.upload_url.is_empty() {
        let body = file
            .slice()
            .map_err(|_| "the browser could not read the selected file".to_string())?;
        client
            .put_cache_object(&admission.upload_url, &body)
            .await
            .map_err(|failure| failure.to_string())?;
        return Ok(format!("Uploaded {byte_size} bytes"));
    }

    upload_cache_file_multipart(client, cache_id, path, file, byte_size).await
}

async fn upload_cache_file_multipart(
    client: ApiClient,
    cache_id: String,
    path: String,
    file: leptos::web_sys::File,
    byte_size: u64,
) -> Result<String, String> {
    let upload = client
        .call::<_, aos_proto_types::BeginCacheMultipartUploadResponse>(
            aos_proto_types::BINARY_CACHE_SERVICE_BEGIN_CACHE_MULTIPART_UPLOAD_PATH,
            &aos_proto_types::BeginCacheMultipartUploadRequest {
                cache_id,
                delivery_url: String::new(),
                path,
                byte_size,
                sha256: String::new(),
            },
        )
        .await
        .map_err(|failure| failure.to_string())?;
    if upload.upload_id.is_empty() || upload.part_size == 0 || upload.part_upload_url.is_empty() {
        return Err("the Hub returned an incomplete multipart upload".to_string());
    }

    let result = upload_cache_parts(&client, &file, byte_size, &upload).await;
    let parts = match result {
        Ok(parts) => parts,
        Err(detail) => {
            let _ = client
                .call::<_, aos_proto_types::CacheMultipartUploadResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_ABORT_CACHE_MULTIPART_UPLOAD_PATH,
                    &aos_proto_types::AbortCacheMultipartUploadRequest {
                        upload_id: upload.upload_id.clone(),
                    },
                )
                .await;
            return Err(detail);
        }
    };
    client
        .call::<_, aos_proto_types::CacheMultipartUploadResponse>(
            aos_proto_types::BINARY_CACHE_SERVICE_COMPLETE_CACHE_MULTIPART_UPLOAD_PATH,
            &aos_proto_types::CompleteCacheMultipartUploadRequest {
                upload_id: upload.upload_id,
                parts,
            },
        )
        .await
        .map_err(|failure| failure.to_string())?;
    Ok(format!("Uploaded {byte_size} bytes in verified parts"))
}

async fn upload_cache_parts(
    client: &ApiClient,
    file: &leptos::web_sys::File,
    byte_size: u64,
    upload: &aos_proto_types::BeginCacheMultipartUploadResponse,
) -> Result<Vec<aos_proto_types::CacheMultipartPart>, String> {
    let mut parts = Vec::new();
    let mut start = 0_u64;
    let mut part_number = 1_u32;
    while start < byte_size {
        let end = start.saturating_add(upload.part_size).min(byte_size);
        let body = file
            .slice_with_f64_and_f64(start as f64, end as f64)
            .map_err(|_| "the browser could not read a multipart file slice".to_string())?;
        let url = format!(
            "{}/{part_number}",
            upload.part_upload_url.trim_end_matches('/')
        );
        let part = client
            .put_cache_object(&url, &body)
            .await
            .map_err(|failure| failure.to_string())?
            .ok_or_else(|| "the Hub omitted the uploaded part receipt".to_string())?;
        if part.part_number != part_number || part.etag.is_empty() {
            return Err("the Hub returned an invalid uploaded part receipt".to_string());
        }
        parts.push(part);
        start = end;
        part_number = part_number
            .checked_add(1)
            .ok_or_else(|| "the selected file requires too many upload parts".to_string())?;
    }
    Ok(parts)
}

#[component]
fn ObjectSearch(client: ApiClient, cache_id: String) -> impl IntoView {
    let query = RwSignal::new(String::new());
    let objects = RwSignal::new(None::<Vec<aos_proto_types::CacheObject>>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let client = client.clone();
        let cache_id = cache_id.clone();
        let query = query.get_untracked().trim().to_string();
        error.set(None);
        objects.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .collect_pages::<_, aos_proto_types::SearchCacheResponse, _, _, _>(
                    aos_proto_types::BINARY_CACHE_SERVICE_SEARCH_CACHE_PATH,
                    move |page_token| aos_proto_types::SearchCacheRequest {
                        cache_id: cache_id.clone(),
                        query: query.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.objects, response.next_page_token),
                )
                .await
            {
                Ok(response) => objects.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Logical Nix content"</p>
                    <h2>"Search objects"</h2>
                    <p>"Search store hashes and names across the complete cache inventory."</p>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label>
                    <span>"Hash or store-name query"</span>
                    <input prop:value=move || query.get() on:input=move |event| query.set(event_target_value(&event))/>
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    {move || if busy.get() { "Searching…" } else { "Search cache" }}
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || objects.get().map(|objects| {
                if objects.is_empty() {
                    view! { <p class="muted">"No matching cache objects."</p> }.into_any()
                } else {
                    view! {
                        <div class="binding-list">
                            {objects.into_iter().map(|object| view! { <CacheObjectCard object=object/> }).collect_view()}
                        </div>
                    }
                    .into_any()
                }
            })}
        </section>
    }
}

#[component]
fn CacheObjectCard(object: aos_proto_types::CacheObject) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{object.store_name}</strong><HashValue value=object.store_hash/></div>
                <StatusBadge state=object.compression.clone() positive=!object.signature.is_empty()/>
            </div>
            <div class="resource-identity">
                <div><span>"NAR hash"</span><HashValue value=object.nar_hash/></div>
                <div><span>"NAR bytes"</span><strong>{object.nar_size}</strong></div>
                <div><span>"File hash"</span><HashValue value=object.file_hash/></div>
                <div><span>"File bytes"</span><strong>{object.file_size}</strong></div>
                <div><span>"References"</span><strong>{object.refs.len()}</strong></div>
                <div><span>"Uploaded"</span><strong>{object.uploaded_at}</strong></div>
            </div>
            <details>
                <summary>"Integrity and derivation metadata"</summary>
                <div class="compact-list">
                    <div class="compact-list-row"><span>"NAR URL"</span><code>{object.nar_url}</code></div>
                    <div class="compact-list-row"><span>"Deriver"</span><code>{display_or(&object.deriver, "none")}</code></div>
                    <div class="compact-list-row"><span>"Content address"</span><code>{display_or(&object.content_address, "none")}</code></div>
                    <div class="compact-list-row"><span>"Signature"</span><code>{display_or(&object.signature, "unsigned")}</code></div>
                    {object.refs.into_iter().map(|reference| view! { <code>{reference}</code> }).collect_view()}
                </div>
            </details>
        </article>
    }
}

#[component]
fn ObjectInspector(client: ApiClient, cache_id: String) -> impl IntoView {
    let store_hash = RwSignal::new(String::new());
    let object = RwSignal::new(None::<aos_proto_types::CacheObject>);
    let closure = RwSignal::new(None::<aos_proto_types::CacheClosureResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let hash = store_hash.get_untracked().trim().to_string();
        if hash.is_empty() {
            error.set(Some("Store hash is required".to_string()));
            return;
        }
        let client = client.clone();
        let cache_id = cache_id.clone();
        error.set(None);
        object.set(None);
        closure.set(None);
        busy.set(true);
        spawn_local(async move {
            let exact = client
                .call::<_, aos_proto_types::GetCacheObjectResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_CACHE_OBJECT_PATH,
                    &aos_proto_types::GetCacheObjectRequest {
                        cache_id: cache_id.clone(),
                        store_hash: hash.clone(),
                    },
                )
                .await;
            match exact {
                Ok(response) => object.set(response.object),
                Err(failure) => {
                    error.set(Some(failure.to_string()));
                    busy.set(false);
                    return;
                }
            }
            match client
                .call::<_, aos_proto_types::CacheClosureResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_CACHE_CLOSURE_PATH,
                    &aos_proto_types::CacheClosureRequest {
                        cache_id,
                        store_hash: hash,
                    },
                )
                .await
            {
                Ok(response) => closure.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Exact recursive view"</p><h2>"Inspect object and closure"</h2></div></div>
            <form class="editor-form" on:submit=on_submit>
                <label><span>"Store hash"</span><input required prop:value=move || store_hash.get() on:input=move |event| store_hash.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Load object and closure"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || object.get().map(|object| view! { <CacheObjectCard object=object/> })}
            {move || closure.get().map(|closure| view! { <ClosureDetail closure=closure/> })}
        </section>
    }
}

#[component]
fn ClosureDetail(closure: aos_proto_types::CacheClosureResponse) -> impl IntoView {
    let missing = closure.nodes.iter().filter(|node| !node.present).count();
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <strong>{format!("{} closure nodes · {} bytes", closure.nodes.len(), closure.total_size)}</strong>
                <StatusBadge state=if missing == 0 { "complete" } else { "incomplete" }.to_string() positive=missing == 0/>
            </div>
            <div class="compact-list">
                {closure.nodes.into_iter().map(|node| view! {
                    <div class="compact-list-row">
                        <div><strong>{node.store_name}</strong><HashValue value=node.store_hash/></div>
                        <span>{format!("{} bytes · {} refs", node.file_size, node.refs.len())}</span>
                        <StatusBadge state=if node.present { "present" } else { "missing" }.to_string() positive=node.present/>
                    </div>
                }).collect_view()}
            </div>
        </article>
    }
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}
