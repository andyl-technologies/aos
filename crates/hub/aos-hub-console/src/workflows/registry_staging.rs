//! Permissioned release candidates, exact inventory progress, and publication.
//!
//! Producers prepare and sign candidate files. The browser reviews their exact
//! revision, resumes missing immutable uploads, and explicitly publishes that
//! revision. Channel assignment remains a separate release workflow.

use std::collections::BTreeSet;

use aos_registry_format::staging::StageRevision;
use leptos::ev::{Event, SubmitEvent};
use leptos::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::components::{CopyableCommand, HashValue, InlineError, StatusBadge};
use crate::mutation::spawn_workflow_task as spawn_local;
use crate::staging::{
    can_edit, can_finalize, progress_percent, resume_command, review_revision, review_stage,
};
use crate::transport::ApiClient;

use super::registry_stage_inventory::StageInventory;

/// Renders private release drafts for a registry with live Publish permission.
#[component]
pub(super) fn RegistryStaging(client: ApiClient, registry: String) -> impl IntoView {
    let selected = RwSignal::new(None::<aos_hub_api::StagedRelease>);
    let refresh = RwSignal::new(0_u64);
    let list_client = client.clone();
    let list_registry = registry.clone();
    let stages = LocalResource::new(move || {
        let _ = refresh.get();
        let client = list_client.clone();
        let registry = list_registry.clone();
        async move {
            client
                .collect_pages::<_, aos_hub_api::ListStagedReleasesResponse, _, _, _>(
                    aos_hub_api::PUBLISH_SERVICE_LIST_STAGED_RELEASES_PATH,
                    move |page_token| aos_hub_api::ListStagedReleasesRequest {
                        registry: registry.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.stages, response.next_page_token),
                )
                .await
        }
    });
    let list_view_client = client.clone();
    let new_client = client.clone();
    let new_registry = registry.clone();

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div><p class="section-kicker">"Release preparation"</p><h2>"Candidates"</h2></div>
                    <button class="secondary-button" type="button" on:click=move |_| refresh.update(|value| *value = value.wrapping_add(1))>"Refresh list"</button>
                </div>
                <p>"Review candidate revisions and finish interrupted uploads. Publish a completed candidate when it is ready for consumers."</p>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading staged releases…"</p> }>
                    {move || {
                        let client = list_view_client.clone();
                        Suspend::new(async move {
                            match stages.await.as_ref() {
                                Ok(records) if records.is_empty() => view! {
                                    <p class="muted">"No staged releases. Upload a prepared candidate below, or stage a release with apr."</p>
                                }.into_any(),
                                Ok(records) => view! {
                                    <div class="binding-list">
                                        {records.iter().cloned().map(|stage| view! {
                                            <StageCard client=client.clone() stage=stage selected=selected/>
                                        }).collect_view()}
                                    </div>
                                }.into_any(),
                                Err(error) => view! { <InlineError detail=error.to_string()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section>
            {move || selected.get().map(|stage| view! {
                <StageDetail client=client.clone() stage=stage selected=selected refresh=refresh/>
            })}
            <details class="panel advanced-controls">
                <summary>"Add a prepared candidate"</summary>
                <p>"Select stage.json or a saved stage record from release preparation. Review its exact commit and inventory before saving."</p>
                <CandidateEditor client=new_client registry=new_registry current=None selected=selected refresh=refresh/>
            </details>
        </div>
    }
}

#[component]
fn StageCard(
    client: ApiClient,
    stage: aos_hub_api::StagedRelease,
    selected: RwSignal<Option<aos_hub_api::StagedRelease>>,
) -> impl IntoView {
    let title = stage.release_id.clone();
    let revision_number = stage.revision;
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let progress = progress_percent(&stage);
    let stage_id = stage.stage_id.clone();
    let registry = stage.registry.clone();
    let inspect = move |_| {
        let client = client.clone();
        let request = aos_hub_api::GetStagedReleaseRequest {
            registry: registry.clone(),
            stage_id: stage_id.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_hub_api::StagedRelease>(
                    aos_hub_api::PUBLISH_SERVICE_GET_STAGED_RELEASE_PATH,
                    &request,
                )
                .await
            {
                Ok(stage) => selected.set(Some(stage)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{title}</strong><code>{stage.stage_id}</code></div>
                <StatusBadge state=stage.state.clone() positive=matches!(stage.state.as_str(), "ready" | "released")/>
            </div>
            <div class="resource-identity">
                <div><span>"Revision"</span><strong>{revision_number}</strong></div>
                <div><span>"Uploaded"</span><strong>{format!("{} / {} bytes ({progress}%)", stage.uploaded_bytes, stage.total_bytes)}</strong></div>
                <div><span>"Objects"</span><strong>{stage.object_count}</strong></div>
                <div><span>"Remaining objects"</span><strong>{stage.missing_object_count}</strong></div>
            </div>
            <button class="secondary-button" type="button" disabled=move || busy.get() on:click=inspect>"Review candidate"</button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        </article>
    }
}

#[component]
fn StageDetail(
    client: ApiClient,
    stage: aos_hub_api::StagedRelease,
    selected: RwSignal<Option<aos_hub_api::StagedRelease>>,
    refresh: RwSignal<u64>,
) -> impl IntoView {
    let revision = match review_stage(&stage) {
        Ok(value) => value,
        Err(error) => return view! { <InlineError detail=error/> }.into_any(),
    };
    let edit = can_edit(&stage);
    let progress = progress_percent(&stage);
    let progress_error = RwSignal::new(None::<String>);
    let stage_client = client.clone();
    let stage_registry = stage.registry.clone();
    let stage_id = stage.stage_id.clone();
    let on_refresh = Callback::new(move |()| {
        refresh_stage(
            stage_client.clone(),
            stage_registry.clone(),
            stage_id.clone(),
            selected,
            refresh,
            progress_error,
        );
    });
    let local_registry = RwSignal::new(String::new());
    let resume_revision = revision.clone();
    let uploads_client = client.clone();
    let publication_id = stage.publication_id.clone();
    let uploads = LocalResource::new(move || {
        let client = uploads_client.clone();
        let publication_id = publication_id.clone();
        async move {
            if publication_id.is_empty() {
                return Ok(None);
            }
            client
                .call::<_, aos_hub_api::RegistryPublication>(
                    aos_hub_api::PUBLISH_SERVICE_GET_REGISTRY_PUBLICATION_PATH,
                    &aos_hub_api::GetRegistryPublicationRequest { publication_id },
                )
                .await
                .map(Some)
        }
    });
    let upload_view_client = client.clone();
    let upload_paths = stage.missing_paths.iter().cloned().collect::<BTreeSet<_>>();
    let update_registry = stage.registry.clone();
    let update_revision = revision.clone();

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div><p class="section-kicker">"Candidate review"</p><h2>{revision.release_id.clone()}</h2><code>{revision.id.clone()}</code></div>
                <StatusBadge state=stage.state.clone() positive=matches!(stage.state.as_str(), "ready" | "released")/>
            </div>
            <div class="resource-identity">
                <div><span>"Revision"</span><strong>{revision.revision}</strong></div>
                <div><span>"Source branch"</span><code>{revision.source_branch.clone()}</code></div>
                <div><span>"Exact commit"</span><HashValue value=revision.commit.clone()/></div>
                <div><span>"Inventory"</span><HashValue value=revision.inventory_digest.clone()/></div>
            </div>
            <p>{format!("{} / {} bytes uploaded · {} bytes verified · {} objects remaining", stage.uploaded_bytes, stage.total_bytes, stage.verified_bytes, stage.missing_object_count)}</p>
            <progress class="stage-progress" value=progress max="100" aria-label="Candidate upload progress">{format!("{progress}%")}</progress>
            <div class="form-actions"><button class="secondary-button" type="button" on:click=move |_| on_refresh.run(())>"Refresh progress"</button><button class="secondary-button" type="button" on:click=move |_| selected.set(None)>"Close review"</button></div>
            {move || progress_error.get().map(|detail| view! { <InlineError detail=detail/> })}
            <h3>"Exact artifact inventory"</h3>
            <StageInventory inventory=revision.inventory.clone() missing_paths=stage.missing_paths.clone()/>
            {(!stage.missing_paths.is_empty() && edit).then(|| view! {
                <section class="subworkflow">
                    <h3>"Finish uploads"</h3>
                    <p>"Resume from the release working directory. Verified objects are reused; incomplete transfers are checked and retried."</p>
                    <label><span>"Local registry name"</span><input placeholder="YOUR-CONFIGURED-REGISTRY" prop:value=move || local_registry.get() on:input=move |event| local_registry.set(event_target_value(&event))/></label>
                    <p class="muted">"Use the registry name in your local apr configuration that points to this Hub registry. Replace YOUR-CONFIGURED-REGISTRY before running the command."</p>
                    {move || view! { <CopyableCommand client="apr" action="resume command" command=resume_command(&resume_revision, &local_registry.get())/> }}
                    <p>"For an individual missing object, select its exact file below. Larger objects use the resume command."</p>
                    <p class="muted">"Individual file controls show up to 50 missing objects. The resume command handles the full inventory."</p>
                    <Suspense fallback=move || view! { <p class="loading-row">"Loading upload destinations…"</p> }>
                        {move || {
                            let client = upload_view_client.clone();
                            let paths = upload_paths.clone();
                            Suspend::new(async move {
                                match uploads.await.as_ref() {
                                    Ok(Some(publication)) => view! {
                                        <div class="binding-list">{publication.objects.iter().filter(|object| paths.contains(&object.path) && object.kind == "immutable").take(crate::staging::INVENTORY_PAGE_SIZE).cloned().map(|object| view! {
                                            <StageObjectUpload client=client.clone() object=object on_uploaded=on_refresh/>
                                        }).collect_view()}</div>
                                    }.into_any(),
                                    Ok(None) => view! { <p class="muted">"Resume with apr to create the upload session."</p> }.into_any(),
                                    Err(error) => view! { <InlineError detail=error.to_string()/> }.into_any(),
                                }
                            })
                        }}
                    </Suspense>
                </section>
            })}
            {edit.then(|| view! {
                <details class="advanced-controls">
                    <summary>"Update candidate revision"</summary>
                    <p>"Prepare the next revision after changing packages, images, or containers. Review the replacement commit and inventory before saving."</p>
                    <CandidateEditor client=client.clone() registry=update_registry current=Some(update_revision) selected=selected refresh=refresh publication_id=stage.publication_id.clone()/>
                </details>
            })}
            <StageLifecycle client=client stage=stage revision=revision selected=selected refresh=refresh/>
        </section>
    }.into_any()
}

fn refresh_stage(
    client: ApiClient,
    registry: String,
    stage_id: String,
    selected: RwSignal<Option<aos_hub_api::StagedRelease>>,
    refresh: RwSignal<u64>,
    error: RwSignal<Option<String>>,
) {
    error.set(None);
    spawn_local(async move {
        match client
            .call::<_, aos_hub_api::StagedRelease>(
                aos_hub_api::PUBLISH_SERVICE_GET_STAGED_RELEASE_PATH,
                &aos_hub_api::GetStagedReleaseRequest { registry, stage_id },
            )
            .await
        {
            Ok(stage) => {
                selected.set(Some(stage));
                refresh.update(|value| *value = value.wrapping_add(1));
            }
            Err(failure) => error.set(Some(failure.to_string())),
        }
    });
}

#[component]
fn StageObjectUpload(
    client: ApiClient,
    object: aos_hub_api::RegistryPublicationObject,
    on_uploaded: Callback<()>,
) -> impl IntoView {
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let available = !object.upload_url.is_empty();
    let expected_size = object.byte_size;
    let upload_label = format!("Upload exact file for {}", object.path);
    let upload_url = object.upload_url.clone();
    let on_file = move |event: Event| {
        let input = event_target::<leptos::web_sys::HtmlInputElement>(&event);
        let Some(file) = input.files().and_then(|files| files.get(0)) else {
            return;
        };
        if file.size() != expected_size as f64 {
            error.set(Some(format!(
                "Select the exact file: expected {expected_size} bytes, selected {}.",
                file.size()
            )));
            return;
        }
        let client = client.clone();
        let upload_url = upload_url.clone();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client.put_publication_object(&upload_url, &file).await {
                Ok(()) => on_uploaded.run(()),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <article class="revision-card">
            <strong><code>{object.path}</code></strong>
            <p>{format!("{} bytes", object.byte_size)}</p>
            <input type="file" aria-label=upload_label disabled=move || !available || busy.get() on:change=on_file/>
            {(!available).then(|| view! { <p class="muted">"Use the resume command for this large object."</p> })}
            {move || busy.get().then(|| view! { <p role="status">"Uploading and verifying…"</p> })}
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        </article>
    }
}

#[component]
fn CandidateEditor(
    client: ApiClient,
    registry: String,
    current: Option<StageRevision>,
    selected: RwSignal<Option<aos_hub_api::StagedRelease>>,
    refresh: RwSignal<u64>,
    #[prop(default = String::new())] publication_id: String,
) -> impl IntoView {
    let pending = RwSignal::new(None::<(Vec<u8>, StageRevision)>);
    let publication = RwSignal::new(publication_id);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let file_epoch = RwSignal::new(0_u64);
    let file_registry = registry.clone();
    let expected_revision = current.as_ref().map(|value| value.revision).unwrap_or(0);
    let on_file = move |event: Event| {
        pending.set(None);
        error.set(None);
        file_epoch.update(|epoch| *epoch = epoch.wrapping_add(1));
        let epoch = file_epoch.get_untracked();
        let input = event_target::<leptos::web_sys::HtmlInputElement>(&event);
        let Some(file) = input.files().and_then(|files| files.get(0)) else {
            return;
        };
        if file.size() > aos_registry_format::staging::wire::MAX_DECODED_REVISION_BYTES as f64 {
            error.set(Some("The candidate file exceeds the 32 MiB limit.".into()));
            return;
        }
        let registry = file_registry.clone();
        let current = current.clone();
        spawn_local(async move {
            let result = match JsFuture::from(file.text()).await {
                Ok(value) => value
                    .as_string()
                    .ok_or_else(|| "Cannot read candidate file.".to_string()),
                Err(_) => Err("Cannot read candidate file.".to_string()),
            }
            .and_then(|json| review_revision(&json, &registry, current.as_ref()))
            .and_then(|revision| {
                aos_registry_format::staging::wire::encode_revision(&revision)
                    .map(|gzip| (gzip, revision))
                    .map_err(|error| format!("Cannot prepare the reviewed candidate: {error}"))
            });
            if file_epoch.get_untracked() != epoch {
                return;
            }
            match result {
                Ok(value) => pending.set(Some(value)),
                Err(detail) => error.set(Some(detail)),
            }
        });
    };
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let Some((revision_gzip, _)) = pending.get_untracked() else {
            return;
        };
        let request = aos_hub_api::UpsertStagedReleaseRequest {
            registry: registry.clone(),
            revision_json: String::new(),
            revision_gzip,
            expected_revision,
            publication_id: publication.get_untracked().trim().to_string(),
        };
        let client = client.clone();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_hub_api::StagedRelease>(
                    aos_hub_api::PUBLISH_SERVICE_UPSERT_STAGED_RELEASE_PATH,
                    &request,
                )
                .await
            {
                Ok(stage) => {
                    selected.set(Some(stage));
                    pending.set(None);
                    refresh.update(|value| *value = value.wrapping_add(1));
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <form class="editor-form" on:submit=on_submit>
            <label class="full-field"><span>"Prepared candidate file"</span><input type="file" accept="application/json,.json" disabled=move || busy.get() on:change=on_file/></label>
            <label class="full-field"><span>"Upload session ID"</span><input prop:value=move || publication.get() disabled=move || busy.get() on:input=move |event| publication.set(event_target_value(&event))/><small>"Use the session created during release preparation, or leave empty until uploads begin."</small></label>
            {move || pending.get().map(|(_, revision)| view! {
                <div class="resource-identity full-field">
                    <div><span>"Release"</span><strong>{revision.release_id}</strong></div>
                    <div><span>"Stage"</span><code>{revision.id}</code></div>
                    <div><span>"Revision"</span><strong>{revision.revision}</strong></div>
                    <div><span>"Source branch"</span><code>{revision.source_branch}</code></div>
                    <div><span>"Exact commit"</span><HashValue value=revision.commit/></div>
                    <div><span>"Inventory"</span><HashValue value=revision.inventory_digest/></div>
                    <div><span>"Objects"</span><strong>{revision.inventory.len()}</strong></div>
                    <details class="full-field">
                        <summary>"Candidate artifact inventory"</summary>
                        <StageInventory inventory=revision.inventory/>
                    </details>
                </div>
            })}
            <button class="secondary-button" type="submit" disabled=move || busy.get() || pending.get().is_none()>{if expected_revision == 0 { "Save reviewed candidate" } else { "Save reviewed revision" }}</button>
        </form>
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
    }
}

#[component]
fn StageLifecycle(
    client: ApiClient,
    stage: aos_hub_api::StagedRelease,
    revision: StageRevision,
    selected: RwSignal<Option<aos_hub_api::StagedRelease>>,
    refresh: RwSignal<u64>,
) -> impl IntoView {
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let confirmed = RwSignal::new(false);
    let editable = can_edit(&stage);
    let publishable = can_finalize(&stage);
    let releasing = stage.state == "releasing";
    let release_href = format!("/{}/-/releases/{}", stage.registry, revision.release_id);
    let channel_href = format!("/{}/-/channels", stage.registry);
    let finalize_client = client.clone();
    let finalize = aos_hub_api::FinalizeStagedReleaseRequest {
        registry: stage.registry.clone(),
        stage_id: stage.stage_id.clone(),
        expected_revision: revision.revision,
        release_id: revision.release_id,
    };
    let publish = move |_| {
        if busy.get_untracked() || (!releasing && !confirmed.get_untracked()) {
            return;
        }
        let client = finalize_client.clone();
        let request = finalize.clone();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_hub_api::StagedRelease>(
                    aos_hub_api::PUBLISH_SERVICE_FINALIZE_STAGED_RELEASE_PATH,
                    &request,
                )
                .await
            {
                Ok(stage) => {
                    selected.set(Some(stage));
                    refresh.update(|value| *value = value.wrapping_add(1));
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    let discard = aos_hub_api::DiscardStagedReleaseRequest {
        registry: stage.registry.clone(),
        stage_id: stage.stage_id.clone(),
        expected_revision: revision.revision,
    };
    let discard_confirmation = RwSignal::new(String::new());
    let discard_id = stage.stage_id.clone();
    let on_discard = move |_| {
        if busy.get_untracked() || discard_confirmation.get_untracked() != discard_id {
            return;
        }
        let client = client.clone();
        let request = discard.clone();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_hub_api::StagedRelease>(
                    aos_hub_api::PUBLISH_SERVICE_DISCARD_STAGED_RELEASE_PATH,
                    &request,
                )
                .await
            {
                Ok(stage) => {
                    selected.set(Some(stage));
                    refresh.update(|value| *value = value.wrapping_add(1));
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    let confirmation_id = stage.stage_id.clone();

    view! {
        <section class="subworkflow">
            <h3>"Publish release"</h3>
            {if stage.state == "released" {
                view! { <p>"This exact revision is published. "<a href=release_href>"View release"</a></p> }.into_any()
            } else if stage.state == "discarded" {
                view! { <p>"This stage was discarded."</p> }.into_any()
            } else {
                view! {
                    <p>"Publishing freezes this revision and makes its signed release available to consumers. Channel assignments are managed separately."</p>
                    {(!publishable).then(|| view! { <p class="muted">"Complete the candidate uploads and refresh progress before publishing."</p> })}
                    {releasing.then(|| view! { <p role="status">"Publication has started. Refresh progress or continue publication to confirm completion."</p> })}
                    {(!releasing).then(|| view! { <label class="checkbox-field"><input type="checkbox" prop:checked=move || confirmed.get() on:change=move |event| confirmed.set(event_target_checked(&event))/><span>"I reviewed this exact commit and artifact inventory."</span></label> })}
                    <button class="button" type="button" disabled=move || busy.get() || !publishable || (!releasing && !confirmed.get()) on:click=publish>{if releasing { "Continue publication" } else { "Publish reviewed release" }}</button>
                }.into_any()
            }}
            <p><a href=channel_href>"View channel assignments"</a></p>
            {editable.then(|| view! {
                <details class="danger-subworkflow">
                    <summary>"Discard stage"</summary>
                    <p>"Discarding relinquishes this candidate’s retained artifacts. Type its stage ID to confirm."</p>
                    <label><span>"Stage ID"</span><input prop:value=move || discard_confirmation.get() on:input=move |event| discard_confirmation.set(event_target_value(&event))/></label>
                    <button class="danger-button" type="button" disabled=move || busy.get() || discard_confirmation.get() != confirmation_id on:click=on_discard>"Discard confirmed stage"</button>
                </details>
            })}
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        </section>
    }
}
