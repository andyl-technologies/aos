//! Editors for committed registry identity, presentation, and support metadata.
//!
//! A reviewed save creates a signed draft. The result includes the maintainer
//! command required to promote it; operational settings use a separate form.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{InlineError, ReviewedPlanCard};
use crate::mutation::{
    idempotency_key, spawn_workflow_task as spawn_local, watch_draft, PendingPlan,
};
use crate::transport::ApiClient;

/// Loads the indexed metadata independently of operational registry settings.
#[component]
pub(super) fn RegistryMetadata(client: ApiClient, slug: String) -> impl IntoView {
    let read_client = client.clone();
    let read_slug = slug.clone();
    let resource = LocalResource::new(move || {
        let client = read_client.clone();
        let slug = read_slug.clone();
        async move {
            client
                .call::<_, aos_proto_types::RegistryMetadataResponse>(
                    aos_proto_types::REGISTRY_SERVICE_GET_REGISTRY_METADATA_PATH,
                    &aos_proto_types::GetRegistryRequest { slug },
                )
                .await
        }
    });

    view! {
        <section class="panel editor-panel">
            <div class="section-heading"><div>
                <h2>"Registry details"</h2>
                <p>"Edit the registry's committed metadata. Saving creates a draft for a maintainer to publish."</p>
            </div></div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading registry details…"</p> }>
                {move || {
                    let client = client.clone();
                    let slug = slug.clone();
                    Suspend::new(async move {
                        match resource.await.as_ref() {
                            Ok(response) => match response.metadata.clone() {
                                Some(metadata) => view! {
                                    <MetadataEditor client=client slug=slug metadata=metadata version=response.resource_version.clone()/>
                                }.into_any(),
                                None => view! { <InlineError detail="The Hub omitted the registry metadata.".to_string()/> }.into_any(),
                            },
                            Err(failure) => view! {
                                <InlineError detail=failure.to_string()/>
                                <p class="field-note">"A registry needs an indexed publication before its committed metadata can be edited."</p>
                            }.into_any(),
                        }
                    })
                }}
            </Suspense>
        </section>
    }
}

#[component]
fn MetadataEditor(
    client: ApiClient,
    slug: String,
    metadata: aos_proto_types::RegistryMetadata,
    version: String,
) -> impl IntoView {
    let can_manage = client.allows("registry.configure");
    let name = RwSignal::new(metadata.name.clone());
    let description = RwSignal::new(metadata.description.clone());
    let readme = RwSignal::new(metadata.readme.clone());
    let default_release = RwSignal::new(metadata.default_release.clone());
    let support = RwSignal::new(metadata.support_toml.clone());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let saved = RwSignal::new(None::<aos_proto_types::RegistryMetadataChangeResponse>);
    let draft_epoch = watch_draft(
        move || {
            let _ = (
                name.get(),
                description.get(),
                readme.get(),
                default_release.get(),
                support.get(),
            );
        },
        pending,
        error,
    );

    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
        error.set(None);
        let desired = aos_proto_types::RegistryMetadata {
            name: name.get_untracked().trim().to_string(),
            description: description.get_untracked().trim().to_string(),
            readme: readme.get_untracked(),
            default_release: default_release.get_untracked().trim().to_string(),
            support_toml: support.get_untracked(),
        };
        let update_mask = metadata_update_mask(&metadata, &desired);
        if update_mask.is_empty() {
            error.set(Some("There are no changes to review.".to_string()));
            return;
        }

        let client = plan_client.clone();
        let planned_epoch = draft_epoch.get_untracked();
        let idempotency_key = idempotency_key("registry-metadata");
        let request = aos_proto_types::PlanUpdateRegistryMetadataRequest {
            slug: slug.clone(),
            desired: Some(desired),
            update_mask,
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::REGISTRY_SERVICE_PLAN_UPDATE_REGISTRY_METADATA_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            if draft_epoch.get_untracked() == planned_epoch {
                match result {
                    Ok(reviewed) => pending.set(Some(reviewed)),
                    Err(detail) => error.set(Some(detail)),
                }
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
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RegistryMetadataChangeResponse>(
                    aos_proto_types::REGISTRY_SERVICE_UPDATE_REGISTRY_METADATA_PATH,
                    &reviewed.registry_apply(),
                )
                .await
            {
                Ok(response) => {
                    pending.set(None);
                    saved.set(Some(response));
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <form class="editor-form" on:submit=on_plan>
            <fieldset class="full-field" disabled=move || !can_manage || busy.get() || saved.get().is_some()>
                <legend>"Committed metadata"</legend>
                <div class="editor-form">
                    <label><span>"Name"</span><input required maxlength="256"
                        prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/>
                        <span class="field-note">"Changing this name does not change the registry URL."</span>
                    </label>
                    <label><span>"Description"</span><input maxlength="4096"
                        prop:value=move || description.get() on:input=move |event| description.set(event_target_value(&event))/></label>
                    <label class="full-field"><span>"Homepage introduction"</span><textarea rows="6"
                        prop:value=move || readme.get() on:input=move |event| readme.set(event_target_value(&event))/>
                        <span class="field-note">"Optional preamble shown on the registry homepage."</span>
                    </label>
                    <label><span>"Default browser release"</span><input placeholder="Automatic"
                        prop:value=move || default_release.get() on:input=move |event| default_release.set(event_target_value(&event))/>
                        <span class="field-note">"An exact release version. Leave blank for automatic selection. Package-manager tracking is unchanged."</span>
                    </label>
                    <details class="full-field advanced-controls"><summary>"Release support policy"</summary>
                        <label><span>"Support policy (TOML)"</span><textarea rows="10" spellcheck="false"
                            prop:value=move || support.get() on:input=move |event| support.set(event_target_value(&event))/></label>
                        <p class="field-note">"Use [default] and [trains] tables. Keep this policy consistent with the release qualification contract. Leave blank to remove the explicit policy."</p>
                        <pre>{"[default]\nkind = \"standard\"\nsuperseded_after_trains = 2\n\n[trains.\"2026.9\"]\nkind = \"lts\"\nsupported_until = \"2028-09-30\""}</pre>
                    </details>
                </div>
                {can_manage.then(|| view! { <div class="form-actions"><button class="button" type="submit">"Review metadata draft"</button></div> })}
            </fieldset>
        </form>
        {(!can_manage).then(|| view! { <p class="muted">"You have read-only access to this registry."</p> })}
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        {move || pending.get().map(|reviewed| view! {
            <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None)) action_label="Create draft"/>
        })}
        {move || saved.get().map(|response| view! {
            <div class="notice" role="status">
                <h3>"Metadata draft created"</h3>
                <p>"A maintainer must run this command with a registry signing key to publish the change:"</p>
                <pre>{response.merge_command}</pre>
                <p>"The registry details will update after the merged publication is indexed."</p>
            </div>
        })}
    }
}

fn metadata_update_mask(
    before: &aos_proto_types::RegistryMetadata,
    after: &aos_proto_types::RegistryMetadata,
) -> Vec<String> {
    [
        ("name", &before.name, &after.name),
        ("description", &before.description, &after.description),
        ("readme", &before.readme, &after.readme),
        (
            "default_release",
            &before.default_release,
            &after.default_release,
        ),
        ("support_toml", &before.support_toml, &after.support_toml),
    ]
    .into_iter()
    .filter(|(_, before, after)| before != after)
    .map(|(field, _, _)| field.to_string())
    .collect()
}
