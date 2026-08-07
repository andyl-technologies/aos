//! Storage-binding and topology-default workflows.
//!
//! Bindings model storage identity and credentials. Defaults select starting
//! values for future placement and delivery plans; they never move existing
//! objects or rewrite live routes.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::networking::NetworkingWorkflow;
use super::organization_scope::organization_authorization_scope;

/// Renders infrastructure pages handled by this implementation boundary.
#[component]
pub(super) fn InfrastructureWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "storage") => view! {
            <StorageBindings
                client=client
                owner_scope_key="instance".to_string()
                organization_slug=None
            />
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "storage") => view! {
            <OrganizationStorageBindings client=client organization=slug.clone()/>
        }
        .into_any(),
        (ConsoleScope::Instance, "defaults") => {
            view! { <TopologyDefaultsEditor client=client organization=None/> }.into_any()
        }
        (ConsoleScope::Organization { slug }, "defaults") => view! {
            <TopologyDefaultsEditor client=client organization=Some(slug.clone())/>
        }
        .into_any(),
        _ => view! { <NetworkingWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn OrganizationStorageBindings(client: ApiClient, organization: String) -> impl IntoView {
    let resolve_client = client.clone();
    let resolve_slug = organization.clone();
    let scope = LocalResource::new(move || {
        let client = resolve_client.clone();
        let slug = resolve_slug.clone();
        async move { organization_authorization_scope(&client, slug).await }
    });

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Resolving organization scope…"</p> }>
            {move || {
                let client = client.clone();
                let organization = organization.clone();
                Suspend::new(async move {
                    match scope.await.as_ref() {
                        Ok(owner_scope_key) => view! {
                            <StorageBindings
                                client=client
                                owner_scope_key=owner_scope_key.clone()
                                organization_slug=Some(organization)
                            />
                        }
                        .into_any(),
                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn StorageBindings(
    client: ApiClient,
    owner_scope_key: String,
    organization_slug: Option<String>,
) -> impl IntoView {
    let list_client = client.clone();
    let list_scope = owner_scope_key.clone();
    let inventory = LocalResource::new(move || {
        let client = list_client.clone();
        let owner_scope_key = list_scope.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListStorageBindingsResponse, _, _, _>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_LIST_STORAGE_BINDINGS_PATH,
                    move |page_token| aos_proto_types::ListStorageBindingsRequest {
                        owner_scope_key: owner_scope_key.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.storage_bindings, response.next_page_token),
                )
                .await
        }
    });
    let inventory_view_client = client.clone();

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"Storage identity"</p>
                        <h2>"Storage bindings"</h2>
                        <p>"Bindings name provider storage and its capability/credential lifecycle. Placements decide which surfaces use each binding."</p>
                    </div>
                </div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading storage bindings…"</p> }>
                    {move || {
                        let client = inventory_view_client.clone();
                        let organization_slug = organization_slug.clone();
                        Suspend::new(async move {
                            match inventory.await.as_ref() {
                                Ok(bindings) if bindings.is_empty() => view! { <p class="muted">"No storage bindings in this scope."</p> }.into_any(),
                                Ok(bindings) => view! {
                                    <div class="binding-list">
                                        {bindings.iter().cloned().map(|binding| view! {
                                            <StorageBindingCard client=client.clone() binding=binding organization_slug=organization_slug.clone()/>
                                        }).collect_view()}
                                    </div>
                                }.into_any(),
                                Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section>
            <StorageBindingCreate client=client owner_scope_key=owner_scope_key/>
        </div>
    }
}

#[component]
fn StorageBindingCreate(client: ApiClient, owner_scope_key: String) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let kind = RwSignal::new("s3".to_string());
    let root = RwSignal::new(String::new());
    let bucket = RwSignal::new(String::new());
    let prefix = RwSignal::new(String::new());
    let endpoint_scheme = RwSignal::new("https".to_string());
    let endpoint_host = RwSignal::new(String::new());
    let endpoint_port = RwSignal::new("443".to_string());
    let region = RwSignal::new("auto".to_string());
    let access = RwSignal::new("private".to_string());
    let deployment_binding = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let plan_client = client.clone();
    let plan_scope = owner_scope_key;
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let provider = match storage_provider(
            &kind.get_untracked(),
            &root.get_untracked(),
            &bucket.get_untracked(),
            &prefix.get_untracked(),
            &endpoint_scheme.get_untracked(),
            &endpoint_host.get_untracked(),
            &endpoint_port.get_untracked(),
            &region.get_untracked(),
            &access.get_untracked(),
            &deployment_binding.get_untracked(),
        ) {
            Ok(provider) => provider,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("storage-binding-create");
        let request = aos_proto_types::PlanStorageBindingMutationRequest {
            stable_id: String::new(),
            owner_scope_key: plan_scope.clone(),
            spec: Some(aos_proto_types::StorageBindingSpec {
                name: name.get_untracked().trim().to_string(),
                provider: Some(provider),
            }),
            expected_resource_version: String::new(),
            idempotency_key: idempotency_key.clone(),
            update_mask: vec!["spec".to_string()],
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_CREATE_STORAGE_BINDING_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
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
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::StorageBindingResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_CREATE_STORAGE_BINDING_PATH,
                    &reviewed.storage_binding_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="panel editor-panel">
            <h2>"Create storage binding"</h2>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label>
                <label><span>"Provider"</span><select prop:value=move || kind.get() on:change=move |event| kind.set(event_target_value(&event))>
                    <option value="s3">"S3-compatible"</option><option value="r2">"Cloudflare R2 API"</option><option value="deployment-r2">"Worker R2 binding"</option><option value="local-fs">"Local filesystem"</option>
                </select></label>
                {move || match kind.get().as_str() {
                    "local-fs" => view! { <label class="full-field"><span>"Root path"</span><input required placeholder="/var/lib/aos-hub/storage" prop:value=move || root.get() on:input=move |event| root.set(event_target_value(&event))/></label> }.into_any(),
                    "deployment-r2" => view! { <label class="full-field"><span>"Worker R2 binding name"</span><input required placeholder="STORAGE" prop:value=move || deployment_binding.get() on:input=move |event| deployment_binding.set(event_target_value(&event))/></label> }.into_any(),
                    _ => view! {
                        <label><span>"Bucket"</span><input required prop:value=move || bucket.get() on:input=move |event| bucket.set(event_target_value(&event))/></label>
                        <label><span>"Object prefix"</span><input prop:value=move || prefix.get() on:input=move |event| prefix.set(event_target_value(&event))/></label>
                        <label><span>"Endpoint scheme"</span><select prop:value=move || endpoint_scheme.get() on:change=move |event| endpoint_scheme.set(event_target_value(&event))><option value="https">"HTTPS"</option><option value="http">"HTTP"</option></select></label>
                        <label><span>"Endpoint DNS name"</span><input required placeholder="s3.example.com" prop:value=move || endpoint_host.get() on:input=move |event| endpoint_host.set(event_target_value(&event))/></label>
                        <label><span>"Endpoint port"</span><input required type="number" min="1" max="65535" prop:value=move || endpoint_port.get() on:input=move |event| endpoint_port.set(event_target_value(&event))/></label>
                        <label><span>"Signing region"</span><input required prop:value=move || region.get() on:input=move |event| region.set(event_target_value(&event))/></label>
                        <label><span>"Object access"</span><select prop:value=move || access.get() on:change=move |event| access.set(event_target_value(&event))><option value="private">"Private objects"</option><option value="public">"Public objects"</option></select></label>
                    }.into_any(),
                }}
                <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn StorageBindingCard(
    client: ApiClient,
    binding: aos_proto_types::StorageBinding,
    organization_slug: Option<String>,
) -> impl IntoView {
    let health = binding.health.clone().unwrap_or_default();
    let capabilities = binding.capabilities.clone().unwrap_or_default();
    let provider = binding
        .spec
        .as_ref()
        .and_then(|spec| spec.provider.as_ref())
        .map(provider_label)
        .unwrap_or("unknown");

    view! {
        <details class="binding-card">
            <summary>
                <div><span class="resource-kind">{provider}</span><h3>{binding.spec.as_ref().map(|spec| spec.name.clone()).unwrap_or_default()}</h3><code>{binding.stable_id.clone()}</code></div>
                <div class="binding-summary-state"><StatusBadge state=health.state.clone() positive=health.state == "healthy"/><span>{if capabilities.writes_supported { "read/write" } else { "read only" }}</span></div>
            </summary>
            <div class="binding-details">
                <div class="resource-identity">
                    <div><span>"Owner"</span><code>{binding.owner_scope_key.clone()}</code></div>
                    <div><span>"Version"</span><code>{binding.resource_version.clone()}</code></div>
                    <div><span>"Presigned access"</span><strong>{yes_no(capabilities.presigns_supported)}</strong></div>
                    <div><span>"Conditional writes"</span><strong>{yes_no(capabilities.conditional_writes_supported)}</strong></div>
                </div>
                {(!health.error.is_empty()).then(|| view! { <InlineError detail=health.error/> })}
                <div class="subworkflow-grid">
                    <div class="subworkflow-stack">
                        <StorageWriteRevisions client=client.clone() binding=binding.clone() organization_slug=organization_slug/>
                        <StorageCredentialEditor client=client.clone() binding=binding.clone()/>
                        <StorageCredentialValidation client=client.clone() binding=binding.clone()/>
                    </div>
                    <StorageGrantEditor client=client.clone() binding=binding.clone()/>
                </div>
                <StorageBindingDelete client=client binding=binding/>
            </div>
        </details>
    }
}

#[component]
fn StorageWriteRevisions(
    client: ApiClient,
    binding: aos_proto_types::StorageBinding,
    organization_slug: Option<String>,
) -> impl IntoView {
    let Some(storage_binding) = storage_binding_ref(&binding, organization_slug.as_deref()) else {
        return view! { <InlineError detail="The storage binding has no canonical owner reference.".to_string()/> }.into_any();
    };
    let revisions = LocalResource::new(move || {
        let client = client.clone();
        let storage_binding = storage_binding.clone();
        async move {
            client
                .call::<_, aos_proto_types::ListStorageBindingWriteRevisionsResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_LIST_STORAGE_BINDING_WRITE_REVISIONS_PATH,
                    &aos_proto_types::ListStorageBindingWriteRevisionsRequest {
                        storage_binding: Some(storage_binding),
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await
        }
    });
    view! {
        <section class="subworkflow">
            <h4>"Write revisions"</h4>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading revisions…"</p> }>
                {move || Suspend::new(async move {
                    match revisions.await.as_ref() {
                        Ok(response) if response.revisions.is_empty() => view! { <p class="muted">"No validated write revision yet."</p> }.into_any(),
                        Ok(response) => view! { <div class="compact-list">{response.revisions.iter().cloned().map(|revision| view! {
                            <div class="compact-list-row"><div><strong>{format!("Revision {}", revision.revision)}</strong><span>{format!("credential generation {} · {}", revision.write_credential_generation, revision.validation_state)}</span>{(!revision.validation_error.is_empty()).then(|| view! { <small>{revision.validation_error}</small> })}</div><code>{revision.resource_version}</code></div>
                        }).collect_view()}</div> }.into_any(),
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }.into_any()
}

#[component]
fn StorageCredentialEditor(
    client: ApiClient,
    binding: aos_proto_types::StorageBinding,
) -> impl IntoView {
    let purpose = RwSignal::new("write".to_string());
    let secret_ref = RwSignal::new(String::new());
    let fingerprint = RwSignal::new(String::new());
    let generation = RwSignal::new("0".to_string());
    let pending = RwSignal::new(None::<(PendingPlan, bool)>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let binding_id = binding.stable_id;
    let version = binding.resource_version;

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let current_generation = match generation.get_untracked().parse::<i64>() {
            Ok(value) if value >= 0 => value,
            _ => {
                error.set(Some(
                    "Current generation must be zero or greater".to_string(),
                ));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("storage-credential");
        let request = aos_proto_types::PlanStorageBindingCredentialRequest {
            storage_binding_id: binding_id.clone(),
            purpose: purpose.get_untracked().trim().to_string(),
            secret_version_ref: secret_ref.get_untracked().trim().to_string(),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
            expected_current_generation: current_generation,
            credential_fingerprint: fingerprint.get_untracked().trim().to_string(),
        };
        let path = if current_generation == 0 {
            aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_SET_STORAGE_BINDING_CREDENTIAL_PATH
        } else {
            aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_ROTATE_STORAGE_BINDING_CREDENTIAL_PATH
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(path, &request)
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some((reviewed, current_generation > 0))),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };

    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some((reviewed, rotate)) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        let path = if rotate {
            aos_proto_types::STORAGE_BINDING_SERVICE_ROTATE_STORAGE_BINDING_CREDENTIAL_PATH
        } else {
            aos_proto_types::STORAGE_BINDING_SERVICE_SET_STORAGE_BINDING_CREDENTIAL_PATH
        };
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::StorageBindingCredentialResponse>(
                    path,
                    &reviewed.storage_credential_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="subworkflow"><h4>"Credential generation"</h4><p>"Reference a deployment secret version; secret material never enters the Hub API."</p>
            <form class="stacked-form" on:submit=on_plan>
                <label><span>"Purpose"</span><input required prop:value=move || purpose.get() on:input=move |event| purpose.set(event_target_value(&event))/></label>
                <label><span>"Secret version reference"</span><input required autocomplete="off" prop:value=move || secret_ref.get() on:input=move |event| secret_ref.set(event_target_value(&event))/></label>
                <label><span>"Resolved-value SHA-256"</span><input required minlength="64" maxlength="64" autocomplete="off" prop:value=move || fingerprint.get() on:input=move |event| fingerprint.set(event_target_value(&event))/></label>
                <label><span>"Current generation (0 to set first)"</span><input type="number" min="0" prop:value=move || generation.get() on:input=move |event| generation.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Review credential change"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|(reviewed, _)| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn StorageCredentialValidation(
    client: ApiClient,
    binding: aos_proto_types::StorageBinding,
) -> impl IntoView {
    let purpose = RwSignal::new("write".to_string());
    let generation = RwSignal::new(String::new());
    let credential_version = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let binding_id = binding.stable_id;
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let generation_value = match generation.get_untracked().parse::<i64>() {
            Ok(value) if value > 0 => value,
            _ => {
                error.set(Some(
                    "Credential generation must be greater than zero".to_string(),
                ));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("storage-credential-validate");
        let request = aos_proto_types::PlanValidateStorageBindingCredentialRequest {
            storage_binding_id: binding_id.clone(),
            purpose: purpose.get_untracked().trim().to_string(),
            generation: generation_value,
            expected_resource_version: credential_version.get_untracked().trim().to_string(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client.call::<_, aos_proto_types::TopologyPlanResponse>(aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_VALIDATE_STORAGE_BINDING_CREDENTIAL_PATH, &request).await.map_err(|failure| failure.to_string()).and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
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
        spawn_local(async move {
            match client.call::<_, aos_proto_types::OperationResponse>(aos_proto_types::STORAGE_BINDING_SERVICE_VALIDATE_STORAGE_BINDING_CREDENTIAL_PATH, &reviewed.topology_apply()).await {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    view! {
        <section class="subworkflow"><h4>"Validate credential"</h4><p>"Validation runs through the storage controller and records capability evidence."</p>
            <form class="stacked-form" on:submit=on_plan>
                <label><span>"Purpose"</span><input required prop:value=move || purpose.get() on:input=move |event| purpose.set(event_target_value(&event))/></label>
                <label><span>"Credential generation"</span><input required type="number" min="1" prop:value=move || generation.get() on:input=move |event| generation.set(event_target_value(&event))/></label>
                <label><span>"Credential resource version"</span><input required prop:value=move || credential_version.get() on:input=move |event| credential_version.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Review validation"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn StorageGrantEditor(
    client: ApiClient,
    binding: aos_proto_types::StorageBinding,
) -> impl IntoView {
    let consumer_scope = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let binding_id = binding.stable_id.clone();
    let version = binding.resource_version.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("storage-binding-grant");
        let request = aos_proto_types::PlanConsumerScopeGrantRequest {
            resource_kind: "storage_binding".to_string(),
            resource_stable_id: binding_id.clone(),
            resource_generation: 0,
            consumer_scope_key: consumer_scope.get_untracked().trim().to_string(),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
            pin_resolutions: Vec::new(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_GRANT_STORAGE_BINDING_SCOPE_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let grant_client = client.clone();
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ConsumerScopeGrantResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_GRANT_STORAGE_BINDING_SCOPE_PATH,
                    &reviewed.consumer_grant_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="subworkflow"><h4>"Consumer scopes"</h4><p>"Grant explicit use without changing ownership."</p><div class="compact-list">{binding.grants.into_iter().filter(|grant| grant.state == "active").map(|grant| view! { <StorageGrantRow client=grant_client.clone() grant=grant/> }).collect_view()}</div><form class="stacked-form" on:submit=on_plan><label><span>"Consumer scope key"</span><input required placeholder="org:acme or registry:acme/main" prop:value=move || consumer_scope.get() on:input=move |event| consumer_scope.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review grant"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn StorageGrantRow(client: ApiClient, grant: aos_proto_types::ConsumerScopeGrant) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let request_grant = grant.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("storage-binding-revoke");
        let request = aos_proto_types::PlanConsumerScopeGrantRequest {
            resource_kind: request_grant.resource_kind.clone(),
            resource_stable_id: request_grant.resource_stable_id.clone(),
            resource_generation: request_grant.resource_generation,
            consumer_scope_key: request_grant.consumer_scope_key.clone(),
            expected_resource_version: request_grant.resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
            pin_resolutions: Vec::new(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_REVOKE_STORAGE_BINDING_SCOPE_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
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
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ConsumerScopeGrantResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_REVOKE_STORAGE_BINDING_SCOPE_PATH,
                    &reviewed.consumer_grant_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <div class="compact-list-row"><div><code>{grant.consumer_scope_key}</code><span>{format!("{} · {} live pins", grant.grant_kind, grant.live_pin_count)}</span></div><button class="table-action" type="button" disabled=move || busy.get() on:click=on_plan>"Review revoke"</button></div>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })} }
}

#[component]
fn StorageBindingDelete(
    client: ApiClient,
    binding: aos_proto_types::StorageBinding,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let stable_id = binding.stable_id;
    let version = binding.resource_version;
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("storage-binding-delete");
        let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
            stable_id: stable_id.clone(),
            expected_resource_version: Some(version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_DELETE_STORAGE_BINDING_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                    aos_proto_types::STORAGE_BINDING_SERVICE_DELETE_STORAGE_BINDING_PATH,
                    &reviewed.delete_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="subworkflow danger-subworkflow"><h4>"Delete binding"</h4><p>"Deletion is blocked by placements, gateways, defaults, grants, or write-authority evidence."</p><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review deletion"</button>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn TopologyDefaultsEditor(client: ApiClient, organization: Option<String>) -> impl IntoView {
    let read_client = client.clone();
    let read_org = organization.clone();
    let defaults = LocalResource::new(move || {
        let client = read_client.clone();
        let organization = read_org.clone();
        async move {
            match organization { Some(org_slug) => client.call::<_, aos_proto_types::TopologyDefaultsResponse>(aos_proto_types::STORAGE_BINDING_SERVICE_GET_ORGANIZATION_TOPOLOGY_DEFAULTS_PATH, &aos_proto_types::GetOrganizationTopologyDefaultsRequest { org_slug }).await, None => client.call::<_, aos_proto_types::TopologyDefaultsResponse>(aos_proto_types::STORAGE_BINDING_SERVICE_GET_INSTANCE_TOPOLOGY_DEFAULTS_PATH, &aos_proto_types::GetInstanceTopologyDefaultsRequest {}).await }
        }
    });
    view! { <Suspense fallback=move || view! { <p class="loading-row">"Loading topology defaults…"</p> }>{move || { let client = client.clone(); let organization = organization.clone(); Suspend::new(async move { match defaults.await.as_ref() { Ok(response) => match response.defaults.clone() { Some(defaults) => view! { <TopologyDefaultsForm client=client defaults=defaults organization=organization/> }.into_any(), None => view! { <InlineError detail="The Hub omitted topology defaults.".to_string()/> }.into_any() }, Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense> }
}

#[component]
fn TopologyDefaultsForm(
    client: ApiClient,
    defaults: aos_proto_types::TopologyDefaults,
    organization: Option<String>,
) -> impl IntoView {
    let storage_binding = RwSignal::new(defaults.storage_binding_id.clone());
    let domain = RwSignal::new(defaults.domain_id.clone());
    let endpoint = RwSignal::new(defaults.delivery_endpoint_id.clone());
    let endpoint_generation = RwSignal::new(defaults.delivery_endpoint_generation.to_string());
    let gateway = RwSignal::new(defaults.storage_gateway_id.clone());
    let gateway_generation = RwSignal::new(defaults.storage_gateway_generation.to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let version = defaults.resource_version;
    let scope_key = defaults.scope_key;
    let plan_client = client.clone();
    let plan_org = organization.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let parse_generation = |value: String, label: &str| {
            value
                .parse::<i64>()
                .map_err(|_| format!("{label} generation must be an integer"))
        };
        let endpoint_gen = match parse_generation(endpoint_generation.get_untracked(), "Endpoint") {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let gateway_gen = match parse_generation(gateway_generation.get_untracked(), "Gateway") {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("topology-defaults");
        let request = aos_proto_types::PlanSetTopologyDefaultsRequest {
            defaults: Some(aos_proto_types::TopologyDefaults {
                scope_key: scope_key.clone(),
                storage_binding_id: storage_binding.get_untracked().trim().to_string(),
                domain_id: domain.get_untracked().trim().to_string(),
                delivery_endpoint_id: endpoint.get_untracked().trim().to_string(),
                delivery_endpoint_generation: endpoint_gen,
                storage_gateway_id: gateway.get_untracked().trim().to_string(),
                storage_gateway_generation: gateway_gen,
                resource_version: version.clone(),
            }),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        let path = if plan_org.is_some() {
            aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_SET_ORGANIZATION_TOPOLOGY_DEFAULTS_PATH
        } else {
            aos_proto_types::STORAGE_BINDING_SERVICE_PLAN_SET_INSTANCE_TOPOLOGY_DEFAULTS_PATH
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(path, &request)
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        let path = if organization.is_some() {
            aos_proto_types::STORAGE_BINDING_SERVICE_SET_ORGANIZATION_TOPOLOGY_DEFAULTS_PATH
        } else {
            aos_proto_types::STORAGE_BINDING_SERVICE_SET_INSTANCE_TOPOLOGY_DEFAULTS_PATH
        };
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::TopologyDefaultsResponse>(
                    path,
                    &reviewed.topology_defaults_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="panel editor-panel"><div class="section-heading"><div><p class="section-kicker">"Defaults for new plans"</p><h2>"Topology defaults"</h2><p>"These values seed future editors. They never migrate live placements or routes."</p></div></div><form class="editor-form" on:submit=on_plan><label><span>"Storage binding stable ID"</span><input prop:value=move || storage_binding.get() on:input=move |event| storage_binding.set(event_target_value(&event))/></label><label><span>"Domain stable ID"</span><input prop:value=move || domain.get() on:input=move |event| domain.set(event_target_value(&event))/></label><label><span>"Delivery endpoint stable ID"</span><input prop:value=move || endpoint.get() on:input=move |event| endpoint.set(event_target_value(&event))/></label><label><span>"Endpoint generation"</span><input type="number" min="0" prop:value=move || endpoint_generation.get() on:input=move |event| endpoint_generation.set(event_target_value(&event))/></label><label><span>"Storage gateway stable ID"</span><input prop:value=move || gateway.get() on:input=move |event| gateway.set(event_target_value(&event))/></label><label><span>"Gateway generation"</span><input type="number" min="0" prop:value=move || gateway_generation.get() on:input=move |event| gateway_generation.set(event_target_value(&event))/></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review defaults"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[allow(clippy::too_many_arguments)]
fn storage_provider(
    kind: &str,
    root: &str,
    bucket: &str,
    prefix: &str,
    endpoint_scheme: &str,
    endpoint_host: &str,
    endpoint_port: &str,
    region: &str,
    access: &str,
    deployment_binding: &str,
) -> Result<aos_proto_types::storage_binding_spec::Provider, String> {
    use aos_proto_types::storage_binding_spec::Provider;
    match kind {
        "local-fs" if !root.trim().is_empty() => Ok(Provider::LocalFilesystem(
            aos_proto_types::LocalFilesystemStorageProvider {
                root_path: root.trim().to_string(),
            },
        )),
        "deployment-r2" if !deployment_binding.trim().is_empty() => Ok(Provider::DeploymentR2(
            aos_proto_types::DeploymentR2StorageProvider {
                bucket_binding: deployment_binding.trim().to_string(),
            },
        )),
        "s3" | "r2" => {
            let port = endpoint_port
                .parse::<u32>()
                .map_err(|_| "Endpoint port must be an integer".to_string())?;
            if bucket.trim().is_empty()
                || endpoint_host.trim().is_empty()
                || region.trim().is_empty()
                || access.trim().is_empty()
            {
                return Err(
                    "Object storage requires bucket, endpoint, region, and access mode".to_string(),
                );
            }
            let endpoint = Some(aos_proto_types::StorageEndpoint {
                scheme: endpoint_scheme.to_string(),
                host: Some(aos_proto_types::storage_endpoint::Host::DnsName(
                    endpoint_host.trim().to_string(),
                )),
                port,
            });
            if kind == "s3" {
                Ok(Provider::S3(aos_proto_types::S3StorageProvider {
                    bucket: bucket.trim().to_string(),
                    prefix: prefix.trim().to_string(),
                    endpoint,
                    signing_region: region.trim().to_string(),
                    access_mode: access.trim().to_string(),
                }))
            } else {
                Ok(Provider::R2(aos_proto_types::R2StorageProvider {
                    bucket: bucket.trim().to_string(),
                    prefix: prefix.trim().to_string(),
                    endpoint,
                    signing_region: region.trim().to_string(),
                    access_mode: access.trim().to_string(),
                }))
            }
        }
        "local-fs" => Err("Local filesystem storage requires a root path".to_string()),
        "deployment-r2" => Err("Worker R2 storage requires a binding name".to_string()),
        _ => Err("Unsupported storage provider".to_string()),
    }
}

fn provider_label(provider: &aos_proto_types::storage_binding_spec::Provider) -> &'static str {
    match provider {
        aos_proto_types::storage_binding_spec::Provider::LocalFilesystem(_) => "Local filesystem",
        aos_proto_types::storage_binding_spec::Provider::S3(_) => "S3-compatible",
        aos_proto_types::storage_binding_spec::Provider::R2(_) => "Cloudflare R2 API",
        aos_proto_types::storage_binding_spec::Provider::DeploymentR2(_) => "Worker R2 binding",
    }
}
fn storage_binding_ref(
    binding: &aos_proto_types::StorageBinding,
    organization_slug: Option<&str>,
) -> Option<aos_proto_types::StorageBindingRef> {
    let target = if binding.owner_scope_key == "instance" {
        aos_proto_types::storage_binding_ref::Target::InstanceDefault(true)
    } else {
        let org_slug = organization_slug?.to_string();
        let name = binding.spec.as_ref()?.name.clone();
        aos_proto_types::storage_binding_ref::Target::Organization(
            aos_proto_types::OrganizationStorageBindingRef { org_slug, name },
        )
    };
    Some(aos_proto_types::StorageBindingRef {
        target: Some(target),
    })
}
fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}
fn reload() {
    if let Some(window) = leptos::web_sys::window() {
        let _ = window.location().reload();
    }
}
