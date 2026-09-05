//! Storage-binding and topology-default workflows.
//!
//! Bindings model storage identity and credentials. Defaults select starting
//! values for future placement and delivery plans; they never move existing
//! objects or rewrite live routes.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{HelpTooltip, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::gateways::{binding_option_label, endpoint_option_label, gateway_option_label};
use super::networking::NetworkingWorkflow;
use super::organization_scope::organization_authorization_scope;

/// Renders infrastructure pages handled by this implementation boundary.
#[component]
pub(super) fn InfrastructureWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "storage") => view! {
            <Bindings
                client=client
                owner_scope_key="instance".to_string()
                organization_slug=None
                include_granted=false
                creation_only=false
            />
        }
        .into_any(),
        (ConsoleScope::Instance, "storage-new") => view! {
            <Bindings
                client=client
                owner_scope_key="instance".to_string()
                organization_slug=None
                include_granted=false
                creation_only=true
            />
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "storage") => view! {
            <OrganizationBindings client=client organization=slug.clone() creation_only=false/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "storage-new") => view! {
            <OrganizationBindings client=client organization=slug.clone() creation_only=true/>
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
fn OrganizationBindings(
    client: ApiClient,
    organization: String,
    creation_only: bool,
) -> impl IntoView {
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
                            <Bindings
                                client=client
                                owner_scope_key=owner_scope_key.clone()
                                organization_slug=Some(organization)
                                include_granted=true
                                creation_only=creation_only
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
fn Bindings(
    client: ApiClient,
    owner_scope_key: String,
    organization_slug: Option<String>,
    include_granted: bool,
    creation_only: bool,
) -> impl IntoView {
    let can_create = client.allows("binding.manage");
    let list_client = client.clone();
    let list_scope = owner_scope_key.clone();
    let inventory = LocalResource::new(move || {
        let client = list_client.clone();
        let owner_scope_key = list_scope.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListBindingsResponse, _, _, _>(
                    aos_proto_types::BINDING_SERVICE_LIST_BINDINGS_PATH,
                    move |page_token| aos_proto_types::ListBindingsRequest {
                        owner_scope_key: owner_scope_key.clone(),
                        page_size: 100,
                        page_token,
                        include_granted,
                    },
                    |response| (response.bindings, response.next_page_token),
                )
                .await
        }
    });
    let inventory_view_client = client.clone();
    let binding_card_scope = owner_scope_key.clone();
    let inventory_path = organization_slug.as_ref().map_or_else(
        || "/-/instance/bindings".to_string(),
        |slug| format!("/-/org/{slug}/bindings"),
    );

    view! {
        <div class="workflow-stack">
            {(!creation_only).then(|| view! { <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"Storage identity"</p>
                        <div class="section-title">
                            <h2>"Bindings"</h2>
                            <HelpTooltip term="Bindings" summary="Bindings name provider storage and its capability or credential lifecycle. Placements decide which surfaces use each binding."/>
                        </div>
                    </div>
                    {can_create.then(|| organization_slug.as_ref().map_or_else(
                        || "/-/instance/bindings/new".to_string(),
                        |slug| format!("/-/org/{slug}/bindings/new"),
                    )).map(|href| view! { <a class="button" href=href>"Create binding"</a> })}
                </div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading bindings…"</p> }>
                    {move || {
                        let client = inventory_view_client.clone();
                        let organization_slug = organization_slug.clone();
                        let consumer_scope_key = binding_card_scope.clone();
                        Suspend::new(async move {
                            match inventory.await.as_ref() {
                                Ok(bindings) if bindings.is_empty() => view! { <p class="muted">"No bindings in this scope."</p> }.into_any(),
                                Ok(bindings) => view! {
                                    <div class="binding-list">
                                        {bindings.iter().cloned().map(|binding| view! {
                                            <BindingCard client=client.clone() binding=binding organization_slug=organization_slug.clone() consumer_scope_key=consumer_scope_key.clone()/>
                                        }).collect_view()}
                                    </div>
                                }.into_any(),
                                Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section> })}
            {creation_only.then(|| view! { <BindingCreate client=client owner_scope_key=owner_scope_key return_path=inventory_path/> })}
        </div>
    }
}

#[component]
fn BindingCreate(client: ApiClient, owner_scope_key: String, return_path: String) -> impl IntoView {
    let stable_id = RwSignal::new(String::new());
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
    let deployment_binding = RwSignal::new("REGISTRY_BUCKET".to_string());
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
        let request = aos_proto_types::PlanBindingMutationRequest {
            stable_id: stable_id.get_untracked().trim().to_string(),
            owner_scope_key: plan_scope.clone(),
            spec: Some(aos_proto_types::BindingSpec {
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
                    aos_proto_types::BINDING_SERVICE_PLAN_CREATE_BINDING_PATH,
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
                .call::<_, aos_proto_types::BindingResponse>(
                    aos_proto_types::BINDING_SERVICE_CREATE_BINDING_PATH,
                    &reviewed.binding_apply(),
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
            <div class="section-heading"><div><p class="section-kicker">"Storage connection"</p><h2>"Create binding"</h2><p>"Name one storage provider connection. Credentials are attached and validated after creation."</p></div></div>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Stable ID"</span><input required placeholder="binding:primary" prop:value=move || stable_id.get() on:input=move |event| stable_id.set(event_target_value(&event))/></label>
                <label><span>"Name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label>
                <label><span>"Provider"</span><select prop:value=move || kind.get() on:change=move |event| kind.set(event_target_value(&event))>
                    <option value="s3">"S3-compatible"</option><option value="r2">"Cloudflare R2 API"</option><option value="deployment-r2">"Worker R2 binding"</option><option value="local-fs">"Local filesystem"</option>
                </select></label>
                {move || match kind.get().as_str() {
                    "local-fs" => view! { <label class="full-field"><span>"Root path"</span><input required placeholder="/var/lib/aos-hub/storage" prop:value=move || root.get() on:input=move |event| root.set(event_target_value(&event))/></label> }.into_any(),
                    "deployment-r2" => view! { <label class="full-field"><span>"Worker R2 runtime attachment"</span><input required readonly aria-readonly="true" prop:value=move || deployment_binding.get()/></label> }.into_any(),
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
                <div class="form-actions"><a class="secondary-button" href=return_path>"Cancel"</a><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn BindingCard(
    client: ApiClient,
    binding: aos_proto_types::Binding,
    organization_slug: Option<String>,
    consumer_scope_key: String,
) -> impl IntoView {
    let health = binding.health.clone().unwrap_or_default();
    let capabilities = binding.capabilities.clone().unwrap_or_default();
    let provider = binding
        .spec
        .as_ref()
        .and_then(|spec| spec.provider.as_ref())
        .map(provider_label)
        .unwrap_or("unknown");
    let provider_details = binding
        .spec
        .as_ref()
        .and_then(storage_provider_details)
        .unwrap_or_default();
    let owned = binding.owner_scope_key == consumer_scope_key;
    let can_manage = owned && client.allows("binding.manage");
    let can_grant = owned && client.allows("binding.grant");
    let controls_requested = RwSignal::new(false);

    view! {
        <details class="binding-card" on:toggle=move |_| controls_requested.set(true)>
            <summary>
                <div><span class="resource-kind">{if owned { provider } else { "granted" }}</span><h3>{binding.spec.as_ref().map(|spec| spec.name.clone()).unwrap_or_default()}</h3><code>{binding.stable_id.clone()}</code></div>
                <div class="binding-summary-state"><StatusBadge state=health.state.clone() positive=health.state == "healthy"/><span>{if capabilities.writes_supported { "read/write" } else { "read only" }}</span></div>
            </summary>
            <div class="binding-details">
                <div class="resource-identity">
                    <div><span>"Owner"</span><code>{binding.owner_scope_key.clone()}</code></div>
                    <div><span>"Version"</span><code>{binding.resource_version.clone()}</code></div>
                    {provider_details.into_iter().map(|(label, value)| view! {
                        <div><span>{label}</span><code>{value}</code></div>
                    }).collect_view()}
                    <div><span>"Presigned access"</span><strong>{yes_no(capabilities.presigns_supported)}</strong></div>
                    <div><span>"Conditional writes"</span><strong>{yes_no(capabilities.conditional_writes_supported)}</strong></div>
                </div>
                {(!health.error.is_empty()).then(|| view! { <InlineError detail=health.error/> })}
                {move || controls_requested.get().then(|| view! {
                    {owned.then(|| view! {
                    <div class="subworkflow-grid">
                        <div class="subworkflow-stack">
                            <StorageWriteRevisions client=client.clone() binding=binding.clone() organization_slug=organization_slug.clone()/>
                            {can_manage.then(|| view! { <StorageCredentialEditor client=client.clone() binding=binding.clone()/> })}
                            {can_manage.then(|| view! { <StorageCredentialValidation client=client.clone() binding=binding.clone()/> })}
                        </div>
                        <StorageGrantEditor client=client.clone() binding=binding.clone() can_grant=can_grant/>
                    </div>
                    {can_manage.then(|| view! { <BindingDelete client=client.clone() binding=binding.clone()/> })}
                    {(!can_manage && !can_grant).then(|| view! { <p class="muted">"You have read-only access to this binding."</p> })}
                    })}
                })}
            </div>
        </details>
    }
}

fn storage_provider_details(
    spec: &aos_proto_types::BindingSpec,
) -> Option<Vec<(&'static str, String)>> {
    use aos_proto_types::binding_spec::Provider;

    let details = match spec.provider.as_ref()? {
        Provider::LocalFilesystem(provider) => {
            vec![("Root path", provider.root_path.clone())]
        }
        Provider::S3(provider) => object_storage_details(
            provider.bucket.clone(),
            provider.prefix.clone(),
            provider.access_mode.clone(),
        ),
        Provider::R2(provider) => object_storage_details(
            provider.bucket.clone(),
            provider.prefix.clone(),
            provider.access_mode.clone(),
        ),
        // The Worker runtime stores the physical R2 bucket name in this field.
        // Calling it a deployment bucket prevents operators from mistaking it
        // for the Worker's JavaScript binding identifier.
        Provider::DeploymentR2(provider) => {
            vec![("Runtime attachment", provider.bucket_binding.clone())]
        }
    };
    Some(details)
}

fn object_storage_details(
    bucket: String,
    prefix: String,
    access_mode: String,
) -> Vec<(&'static str, String)> {
    let mut details = vec![("Bucket", bucket)];
    if !prefix.is_empty() {
        details.push(("Object prefix", prefix));
    }
    if !access_mode.is_empty() {
        details.push(("Access", access_mode));
    }
    details
}

#[component]
fn StorageWriteRevisions(
    client: ApiClient,
    binding: aos_proto_types::Binding,
    organization_slug: Option<String>,
) -> impl IntoView {
    let Some(binding) = binding_ref(&binding, organization_slug.as_deref()) else {
        return view! { <InlineError detail="The binding has no canonical owner reference.".to_string()/> }.into_any();
    };
    let revisions = LocalResource::new(move || {
        let client = client.clone();
        let binding = binding.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListBindingWriteRevisionsResponse, _, _, _>(
                    aos_proto_types::BINDING_SERVICE_LIST_BINDING_WRITE_REVISIONS_PATH,
                    move |page_token| aos_proto_types::ListBindingWriteRevisionsRequest {
                        binding: Some(binding.clone()),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.revisions, response.next_page_token),
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
                        Ok(revisions) if revisions.is_empty() => view! { <p class="muted">"No validated write revision yet."</p> }.into_any(),
                        Ok(revisions) => view! { <div class="compact-list">{revisions.iter().cloned().map(|revision| view! {
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
fn StorageCredentialEditor(client: ApiClient, binding: aos_proto_types::Binding) -> impl IntoView {
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
        let request = aos_proto_types::PlanBindingCredentialRequest {
            binding_id: binding_id.clone(),
            purpose: purpose.get_untracked().trim().to_string(),
            secret_version_ref: secret_ref.get_untracked().trim().to_string(),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
            expected_current_generation: current_generation,
            credential_fingerprint: fingerprint.get_untracked().trim().to_string(),
        };
        let path = if current_generation == 0 {
            aos_proto_types::BINDING_SERVICE_PLAN_SET_BINDING_CREDENTIAL_PATH
        } else {
            aos_proto_types::BINDING_SERVICE_PLAN_ROTATE_BINDING_CREDENTIAL_PATH
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
            aos_proto_types::BINDING_SERVICE_ROTATE_BINDING_CREDENTIAL_PATH
        } else {
            aos_proto_types::BINDING_SERVICE_SET_BINDING_CREDENTIAL_PATH
        };
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::BindingCredentialResponse>(
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
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Change credentials"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|(reviewed, _)| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn StorageCredentialValidation(
    client: ApiClient,
    binding: aos_proto_types::Binding,
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
        let request = aos_proto_types::PlanValidateBindingCredentialRequest {
            binding_id: binding_id.clone(),
            purpose: purpose.get_untracked().trim().to_string(),
            generation: generation_value,
            expected_resource_version: credential_version.get_untracked().trim().to_string(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINDING_SERVICE_PLAN_VALIDATE_BINDING_CREDENTIAL_PATH,
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
                .call::<_, aos_proto_types::OperationResponse>(
                    aos_proto_types::BINDING_SERVICE_VALIDATE_BINDING_CREDENTIAL_PATH,
                    &reviewed.topology_apply(),
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
        <section class="subworkflow"><h4>"Validate credential"</h4><p>"Validation runs through the storage controller and records capability evidence."</p>
            <form class="stacked-form" on:submit=on_plan>
                <label><span>"Purpose"</span><input required prop:value=move || purpose.get() on:input=move |event| purpose.set(event_target_value(&event))/></label>
                <label><span>"Credential generation"</span><input required type="number" min="1" prop:value=move || generation.get() on:input=move |event| generation.set(event_target_value(&event))/></label>
                <label><span>"Credential resource version"</span><input required prop:value=move || credential_version.get() on:input=move |event| credential_version.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Validate"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

#[component]
fn StorageGrantEditor(
    client: ApiClient,
    binding: aos_proto_types::Binding,
    can_grant: bool,
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
            resource_kind: "binding".to_string(),
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
                    aos_proto_types::BINDING_SERVICE_PLAN_GRANT_BINDING_SCOPE_PATH,
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
                    aos_proto_types::BINDING_SERVICE_GRANT_BINDING_SCOPE_PATH,
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
    view! { <section class="subworkflow"><h4>"Consumer scopes"</h4><p>"Grant explicit use without changing ownership."</p><div class="compact-list">{binding.grants.into_iter().filter(|grant| grant.state == "active").map(|grant| view! { <StorageGrantRow client=grant_client.clone() grant=grant can_grant=can_grant/> }).collect_view()}</div>{can_grant.then(|| view! { <form class="stacked-form" on:submit=on_plan><label><span>"Consumer scope key"</span><input required placeholder="org:acme or registry:acme/main" prop:value=move || consumer_scope.get() on:input=move |event| consumer_scope.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review grant"</button></form> })}{can_grant.then(|| view! { {move || error.get().map(|detail| view! { <InlineError detail=detail/> })} {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })} })}</section> }
}

#[component]
fn StorageGrantRow(
    client: ApiClient,
    grant: aos_proto_types::ConsumerScopeGrant,
    can_grant: bool,
) -> impl IntoView {
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
                    aos_proto_types::BINDING_SERVICE_PLAN_REVOKE_BINDING_SCOPE_PATH,
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
                    aos_proto_types::BINDING_SERVICE_REVOKE_BINDING_SCOPE_PATH,
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
    view! { <div class="compact-list-row"><div><code>{grant.consumer_scope_key}</code><span>{format!("{} · {} live pins", grant.grant_kind, grant.live_pin_count)}</span></div>{can_grant.then(|| view! { <button class="table-action" type="button" disabled=move || busy.get() on:click=on_plan>"Review revoke"</button> })}</div>{can_grant.then(|| view! { {move || error.get().map(|detail| view! { <InlineError detail=detail/> })} {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })} })} }
}

#[component]
fn BindingDelete(client: ApiClient, binding: aos_proto_types::Binding) -> impl IntoView {
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
                    aos_proto_types::BINDING_SERVICE_PLAN_DELETE_BINDING_PATH,
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
                    aos_proto_types::BINDING_SERVICE_DELETE_BINDING_PATH,
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
    view! { <section class="subworkflow danger-subworkflow"><h4>"Delete binding"</h4><p>"Deletion is blocked by placements, gateways, defaults, grants, or write-authority evidence."</p><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Delete"</button>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn TopologyDefaultsEditor(client: ApiClient, organization: Option<String>) -> impl IntoView {
    let read_client = client.clone();
    let read_org = organization.clone();
    let defaults = LocalResource::new(move || {
        let client = read_client.clone();
        let organization = read_org.clone();
        async move { load_topology_defaults(&client, organization).await }
    });
    view! { <Suspense fallback=move || view! { <p class="loading-row">"Loading topology defaults and available resources…"</p> }>{move || { let client = client.clone(); let organization = organization.clone(); Suspend::new(async move { match defaults.await.as_ref() { Ok((response, choices)) => match response.defaults.clone() { Some(defaults) => view! { <TopologyDefaultsForm client=client defaults=defaults organization=organization choices=choices.clone()/> }.into_any(), None => view! { <InlineError detail="The Hub omitted topology defaults.".to_string()/> }.into_any() }, Err(failure) => view! { <InlineError detail=failure.clone()/> }.into_any() } }) }}</Suspense> }
}

#[derive(Clone, Debug)]
struct TopologyDefaultChoices {
    bindings: Vec<aos_proto_types::Binding>,
    domains: Vec<aos_proto_types::Domain>,
    endpoints: Vec<aos_proto_types::Endpoint>,
    gateways: Vec<aos_proto_types::Gateway>,
}

async fn load_topology_defaults(
    client: &ApiClient,
    organization: Option<String>,
) -> Result<
    (
        aos_proto_types::TopologyDefaultsResponse,
        TopologyDefaultChoices,
    ),
    String,
> {
    let (defaults, owner_scope_key) = match organization.as_ref() {
        Some(org_slug) => (
            client
                .call::<_, aos_proto_types::TopologyDefaultsResponse>(
                    aos_proto_types::BINDING_SERVICE_GET_ORGANIZATION_TOPOLOGY_DEFAULTS_PATH,
                    &aos_proto_types::GetOrganizationTopologyDefaultsRequest {
                        org_slug: org_slug.clone(),
                    },
                )
                .await
                .map_err(|failure| failure.to_string())?,
            organization_authorization_scope(client, org_slug.clone()).await?,
        ),
        None => (
            client
                .call::<_, aos_proto_types::TopologyDefaultsResponse>(
                    aos_proto_types::BINDING_SERVICE_GET_INSTANCE_TOPOLOGY_DEFAULTS_PATH,
                    &aos_proto_types::GetInstanceTopologyDefaultsRequest {},
                )
                .await
                .map_err(|failure| failure.to_string())?,
            "instance".to_string(),
        ),
    };
    let binding_scope = owner_scope_key.clone();
    let bindings = client.collect_pages::<_, aos_proto_types::ListBindingsResponse, _, _, _>(
        aos_proto_types::BINDING_SERVICE_LIST_BINDINGS_PATH,
        move |page_token| aos_proto_types::ListBindingsRequest {
            owner_scope_key: binding_scope.clone(),
            page_size: 100,
            page_token,
            include_granted: true,
        },
        |response| (response.bindings, response.next_page_token),
    );
    let domain_scope = owner_scope_key.clone();
    let domains = client.collect_pages::<_, aos_proto_types::ListDomainsResponse, _, _, _>(
        aos_proto_types::DOMAIN_SERVICE_LIST_DOMAINS_PATH,
        move |page_token| aos_proto_types::ListDomainsRequest {
            owner_scope_key: domain_scope.clone(),
            page_size: 100,
            page_token,
        },
        |response| (response.domains, response.next_page_token),
    );
    let endpoint_scope = owner_scope_key.clone();
    let endpoints = client.collect_pages::<_, aos_proto_types::ListEndpointsResponse, _, _, _>(
        aos_proto_types::DELIVERY_SERVICE_LIST_ENDPOINTS_PATH,
        move |page_token| aos_proto_types::ListTopologyResourcesRequest {
            owner_scope_key: endpoint_scope.clone(),
            page_size: 100,
            page_token,
            include_granted: true,
        },
        |response| (response.endpoints, response.next_page_token),
    );
    let gateway_scope = owner_scope_key;
    let gateways = client.collect_pages::<_, aos_proto_types::ListGatewaysResponse, _, _, _>(
        aos_proto_types::DELIVERY_SERVICE_LIST_GATEWAYS_PATH,
        move |page_token| aos_proto_types::ListGatewaysRequest {
            binding: None,
            page_size: 100,
            page_token,
            owner_scope_key: gateway_scope.clone(),
            include_granted: true,
        },
        |response| (response.gateways, response.next_page_token),
    );
    let (bindings, domains, endpoints, gateways) =
        futures::join!(bindings, domains, endpoints, gateways);
    let bindings = bindings.map_err(|failure| failure.to_string())?;
    let domains = domains.map_err(|failure| failure.to_string())?;
    let endpoints = endpoints.map_err(|failure| failure.to_string())?;
    let gateways = gateways.map_err(|failure| failure.to_string())?;

    Ok((
        defaults,
        TopologyDefaultChoices {
            bindings,
            domains,
            endpoints,
            gateways,
        },
    ))
}

#[component]
fn TopologyDefaultsForm(
    client: ApiClient,
    defaults: aos_proto_types::TopologyDefaults,
    organization: Option<String>,
    choices: TopologyDefaultChoices,
) -> impl IntoView {
    let current_binding = display_default(&defaults.binding_id);
    let current_domain = display_default(&defaults.domain_id);
    let current_endpoint = generation_default(&defaults.endpoint_id, defaults.endpoint_generation);
    let current_gateway = generation_default(&defaults.gateway_id, defaults.gateway_generation);
    let current_version = if defaults.resource_version.is_empty() {
        "Not yet saved".to_string()
    } else {
        defaults.resource_version.clone()
    };
    let can_manage = client.allows("binding.manage");
    let binding = RwSignal::new(defaults.binding_id.clone());
    let domain = RwSignal::new(defaults.domain_id.clone());
    let endpoint = RwSignal::new(defaults.endpoint_id.clone());
    let endpoint_generation = RwSignal::new(defaults.endpoint_generation.to_string());
    let gateway = RwSignal::new(defaults.gateway_id.clone());
    let gateway_generation = RwSignal::new(defaults.gateway_generation.to_string());
    let endpoint_choices = choices.endpoints.clone();
    let selected_endpoints = choices.endpoints;
    let gateway_choices = choices.gateways.clone();
    let selected_gateways = choices.gateways;
    let on_endpoint_change = move |event| {
        let value = event_target_value(&event);
        endpoint.set(value.clone());
        endpoint_generation.set(
            selected_endpoints
                .iter()
                .find(|choice| choice.stable_id == value)
                .map(|choice| choice.desired_generation.to_string())
                .unwrap_or_else(|| "0".to_string()),
        );
    };
    let on_gateway_change = move |event| {
        let value = event_target_value(&event);
        gateway.set(value.clone());
        gateway_generation.set(
            selected_gateways
                .iter()
                .find(|choice| choice.stable_id == value)
                .map(|choice| choice.desired_generation.to_string())
                .unwrap_or_else(|| "0".to_string()),
        );
    };
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
                binding_id: binding.get_untracked().trim().to_string(),
                domain_id: domain.get_untracked().trim().to_string(),
                endpoint_id: endpoint.get_untracked().trim().to_string(),
                endpoint_generation: endpoint_gen,
                gateway_id: gateway.get_untracked().trim().to_string(),
                gateway_generation: gateway_gen,
                resource_version: version.clone(),
            }),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        let path = if plan_org.is_some() {
            aos_proto_types::BINDING_SERVICE_PLAN_SET_ORGANIZATION_TOPOLOGY_DEFAULTS_PATH
        } else {
            aos_proto_types::BINDING_SERVICE_PLAN_SET_INSTANCE_TOPOLOGY_DEFAULTS_PATH
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
            aos_proto_types::BINDING_SERVICE_SET_ORGANIZATION_TOPOLOGY_DEFAULTS_PATH
        } else {
            aos_proto_types::BINDING_SERVICE_SET_INSTANCE_TOPOLOGY_DEFAULTS_PATH
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
    view! { <div class="workflow-stack"><section class="panel effective-overview"><div class="section-heading"><div><p class="section-kicker">"Defaults for future workflows"</p><h2>"Topology defaults"</h2><p>"New storage and delivery plans start from these choices. Existing placements and routes do not change."</p></div></div><div class="resource-identity"><div><span>"Binding"</span><code>{current_binding}</code></div><div><span>"Domain"</span><code>{current_domain}</code></div><div><span>"Endpoint"</span><code>{current_endpoint}</code></div><div><span>"Gateway"</span><code>{current_gateway}</code></div></div><details><summary>"Configuration metadata"</summary><div class="resource-identity"><div><span>"Version"</span><code>{current_version}</code></div></div></details></section>{if can_manage { view! { <details class="panel advanced-controls"><summary>"Change topology defaults"</summary><form class="editor-form" on:submit=on_plan><label><span>"Binding"</span><select prop:value=move || binding.get() on:change=move |event| binding.set(event_target_value(&event))><option value="">"No default"</option>{choices.bindings.iter().map(|choice| view! { <option value=choice.stable_id.clone()>{binding_option_label(choice)}</option> }).collect_view()}</select></label><label><span>"Domain"</span><select prop:value=move || domain.get() on:change=move |event| domain.set(event_target_value(&event))><option value="">"No default"</option>{choices.domains.iter().map(|choice| view! { <option value=choice.stable_id.clone()>{choice.hostname.clone()}</option> }).collect_view()}</select></label><label><span>"Endpoint"</span><select prop:value=move || endpoint.get() on:change=on_endpoint_change><option value="">"No default"</option>{endpoint_choices.iter().map(|choice| view! { <option value=choice.stable_id.clone()>{endpoint_option_label(choice)}</option> }).collect_view()}</select></label><label><span>"Endpoint generation"</span><input readonly aria-readonly="true" prop:value=move || endpoint_generation.get()/></label><label><span>"Gateway"</span><select prop:value=move || gateway.get() on:change=on_gateway_change><option value="">"No default"</option>{gateway_choices.iter().map(|choice| view! { <option value=choice.stable_id.clone()>{gateway_option_label(choice)}</option> }).collect_view()}</select></label><label><span>"Gateway generation"</span><input readonly aria-readonly="true" prop:value=move || gateway_generation.get()/></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review defaults"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</details> }.into_any() } else { view! { <section class="panel"><p class="muted">"You have read-only access to these defaults."</p></section> }.into_any() }}</div> }
}

fn display_default(value: &str) -> String {
    if value.is_empty() {
        "Not set".to_string()
    } else {
        value.to_string()
    }
}

fn generation_default(stable_id: &str, generation: i64) -> String {
    if stable_id.is_empty() {
        "Not set".to_string()
    } else {
        format!("{stable_id} · generation {generation}")
    }
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
) -> Result<aos_proto_types::binding_spec::Provider, String> {
    use aos_proto_types::binding_spec::Provider;
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

fn provider_label(provider: &aos_proto_types::binding_spec::Provider) -> &'static str {
    match provider {
        aos_proto_types::binding_spec::Provider::LocalFilesystem(_) => "Local filesystem",
        aos_proto_types::binding_spec::Provider::S3(_) => "S3-compatible",
        aos_proto_types::binding_spec::Provider::R2(_) => "Cloudflare R2 API",
        aos_proto_types::binding_spec::Provider::DeploymentR2(_) => "Worker R2 binding",
    }
}
fn binding_ref(
    binding: &aos_proto_types::Binding,
    organization_slug: Option<&str>,
) -> Option<aos_proto_types::BindingRef> {
    let target = if binding.owner_scope_key == "instance" {
        aos_proto_types::binding_ref::Target::InstanceDefault(true)
    } else {
        let org_slug = organization_slug?.to_string();
        let name = binding.spec.as_ref()?.name.clone();
        aos_proto_types::binding_ref::Target::Organization(
            aos_proto_types::OrganizationBindingRef { org_slug, name },
        )
    };
    Some(aos_proto_types::BindingRef {
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
    crate::app::refresh();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_binding_displays_runtime_attachment() {
        let spec = aos_proto_types::BindingSpec {
            name: "default".to_string(),
            provider: Some(aos_proto_types::binding_spec::Provider::DeploymentR2(
                aos_proto_types::DeploymentR2StorageProvider {
                    bucket_binding: "REGISTRY_BUCKET".to_string(),
                },
            )),
        };
        assert_eq!(
            storage_provider_details(&spec),
            Some(vec![("Runtime attachment", "REGISTRY_BUCKET".to_string())])
        );
    }
}
