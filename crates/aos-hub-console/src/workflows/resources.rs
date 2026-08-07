//! Organization, project, registry, and binary-cache resource workflows.
//!
//! These pages establish the common inventory/editor grammar: canonical
//! resource identity is always visible, mutable policy is edited separately,
//! and every durable change crosses the immutable plan review boundary.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{EmptyState, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;
use crate::workflows::infrastructure::InfrastructureWorkflow;

use super::organization_scope::organization_authorization_scope;

/// Renders the typed resource adapter owned by the current canonical page.
#[component]
pub(crate) fn ResourceWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Organizations, "overview") => {
            view! { <OrganizationInventory client=client/> }.into_any()
        }
        (ConsoleScope::Organizations, "new") => {
            view! { <OrganizationCreate client=client/> }.into_any()
        }
        (ConsoleScope::Organization { slug }, "overview") => {
            view! { <OrganizationOverview client=client slug=slug.clone()/> }.into_any()
        }
        (ConsoleScope::Organization { slug }, "projects") => {
            view! { <ProjectInventory client=client organization=slug.clone() creation_only=false/> }.into_any()
        }
        (ConsoleScope::Organization { slug }, "projects-new") => {
            view! { <ProjectInventory client=client organization=slug.clone() creation_only=true/> }.into_any()
        }
        (ConsoleScope::Organization { slug }, "registries") => {
            view! { <RegistryInventory client=client organization=slug.clone() creation_only=false/> }.into_any()
        }
        (ConsoleScope::Organization { slug }, "registries-new") => {
            view! { <RegistryInventory client=client organization=slug.clone() creation_only=true/> }.into_any()
        }
        (ConsoleScope::Organization { slug }, "caches") => {
            view! { <OrganizationCacheInventory client=client organization=slug.clone() creation_only=false/> }
                .into_any()
        }
        (ConsoleScope::Organization { slug }, "caches-new") => {
            view! { <OrganizationCacheInventory client=client organization=slug.clone() creation_only=true/> }
                .into_any()
        }
        (ConsoleScope::Organization { slug }, "danger") => {
            view! { <OrganizationDanger client=client slug=slug.clone()/> }.into_any()
        }
        (ConsoleScope::Registry { path }, "overview") => {
            view! { <RegistryOverview client=client slug=path.clone()/> }.into_any()
        }
        (ConsoleScope::Registry { path }, "danger") => {
            view! { <RegistryDanger client=client slug=path.clone()/> }.into_any()
        }
        (
            ConsoleScope::Cache {
                organization,
                cache,
            },
            "overview",
        ) => view! {
            <CacheOverview client=client stable_id=format!("{organization}/{cache}")/>
        }
        .into_any(),
        (
            ConsoleScope::Cache {
                organization,
                cache,
            },
            "danger",
        ) => view! {
            <CacheDanger client=client stable_id=format!("{organization}/{cache}")/>
        }
        .into_any(),
        _ => view! { <InfrastructureWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn OrganizationInventory(client: ApiClient) -> impl IntoView {
    let can_create = client.allows("read");
    let inventory = LocalResource::new(move || {
        let client = client.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListOrganizationsResponse, _, _, _>(
                    aos_proto_types::ORGANIZATION_SERVICE_LIST_ORGANIZATIONS_PATH,
                    |page_token| aos_proto_types::ListOrganizationsRequest {
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.organizations, response.next_page_token),
                )
                .await
        }
    });

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Tenant directory"</p>
                    <h2>"Organizations"</h2>
                    <p>"Organizations own projects, registries, caches, and scoped infrastructure grants."</p>
                </div>
                {can_create.then(|| view! { <a class="button" href="/-/orgs/new">"Create organization"</a> })}
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading organizations…"</p> }>
                {move || Suspend::new(async move {
                    match inventory.await.as_ref() {
                        Ok(organizations) if organizations.is_empty() => view! {
                            <EmptyState
                                title="No organizations yet".to_string()
                                detail="Create the first tenant boundary for managed resources.".to_string()
                                action_label=None
                                action=None
                            />
                        }.into_any(),
                        Ok(organizations) => view! {
                            <div class="resource-grid">
                                {organizations.iter().cloned().map(|organization| {
                                    let href = format!("/-/org/{}", organization.slug);
                                    view! {
                                        <a class="resource-card" href=href>
                                            <div>
                                                <span class="resource-kind">"Organization"</span>
                                                <h3>{organization.display_name}</h3>
                                                <code>{organization.slug}</code>
                                            </div>
                                            <span class="card-arrow" aria-hidden="true">"→"</span>
                                        </a>
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any(),
                        Err(error) => view! { <InlineError detail=error.to_string()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn OrganizationCreate(client: ApiClient) -> impl IntoView {
    let slug = RwSignal::new(String::new());
    let display_name = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("organization-create");
        let request = aos_proto_types::PlanCreateOrganizationRequest {
            slug: slug.get_untracked().trim().to_string(),
            display_name: display_name.get_untracked().trim().to_string(),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: String::new(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_PLAN_CREATE_ORGANIZATION_PATH,
                    &request,
                )
                .await
                .map_err(|error| error.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(plan) => pending.set(Some(plan)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };

    let apply_client = client.clone();
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::OrganizationResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_CREATE_ORGANIZATION_PATH,
                    &reviewed.organization_apply(),
                )
                .await
            {
                Ok(response) => match response.organization {
                    Some(organization) => navigate(&format!("/-/org/{}", organization.slug)),
                    None => error.set(Some(
                        "The Hub omitted the created organization.".to_string(),
                    )),
                },
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="panel editor-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"New tenant"</p>
                    <h2>"Create an organization"</h2>
                    <p>"The slug becomes durable topology identity; the display name remains editable."</p>
                </div>
            </div>
            <form class="editor-form" on:submit=on_plan>
                <label>
                    <span>"Organization slug"</span>
                    <input required maxlength="63" autocomplete="off" prop:value=move || slug.get()
                        on:input=move |event| slug.set(event_target_value(&event)) />
                    <small>"Lowercase URL-safe identity, for example `platform`."</small>
                </label>
                <label>
                    <span>"Display name"</span>
                    <input required maxlength="120" prop:value=move || display_name.get()
                        on:input=move |event| display_name.set(event_target_value(&event)) />
                </label>
                <div class="form-actions">
                    <a class="secondary-button" href="/-/orgs">"Cancel"</a>
                    <button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button>
                </div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| {
                let on_cancel = Callback::new(move |()| pending.set(None));
                view! {
                    <ReviewedPlanCard
                        plan=reviewed.plan
                        applying=busy.get()
                        on_apply=on_apply
                        on_cancel=on_cancel
                    />
                }
            })}
        </section>
    }
}

#[component]
fn OrganizationOverview(client: ApiClient, slug: String) -> impl IntoView {
    let request_slug = slug.clone();
    let resource_client = client.clone();
    let organization = LocalResource::new(move || {
        let client = resource_client.clone();
        let slug = request_slug.clone();
        async move {
            client
                .call::<_, aos_proto_types::OrganizationResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_GET_ORGANIZATION_PATH,
                    &aos_proto_types::GetOrganizationRequest { slug },
                )
                .await
        }
    });

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Loading organization…"</p> }>
            {move || {
                let client = client.clone();
                Suspend::new(async move {
                    match organization.await.as_ref() {
                        Ok(response) => match response.organization.clone() {
                            Some(value) => view! { <OrganizationEditor client=client organization=value/> }.into_any(),
                            None => view! { <InlineError detail="The Hub omitted the organization.".to_string()/> }.into_any(),
                        },
                        Err(error) => view! { <InlineError detail=error.to_string()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn OrganizationEditor(
    client: ApiClient,
    organization: aos_proto_types::Organization,
) -> impl IntoView {
    let display_name = RwSignal::new(organization.display_name.clone());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let slug = organization.slug.clone();
    let resource_version = organization.resource_version.clone();

    let plan_client = client.clone();
    let plan_slug = slug.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("organization-update");
        let request = aos_proto_types::PlanUpdateOrganizationRequest {
            slug: plan_slug.clone(),
            display_name: display_name.get_untracked().trim().to_string(),
            expected_resource_version: resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_PLAN_UPDATE_ORGANIZATION_PATH,
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
    let destination = format!("/-/org/{slug}");
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        let destination = destination.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::OrganizationResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_UPDATE_ORGANIZATION_PATH,
                    &reviewed.organization_apply(),
                )
                .await
            {
                Ok(_) => navigate(&destination),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="panel editor-panel">
            <div class="resource-identity">
                <div><span>"Stable ID"</span><code>{organization.stable_id}</code></div>
                <div><span>"Scope"</span><code>{organization.owner_scope_key}</code></div>
                <div><span>"Version"</span><code>{organization.resource_version}</code></div>
            </div>
            <form class="editor-form" on:submit=on_plan>
                <label>
                    <span>"Organization slug"</span>
                    <input disabled value=organization.slug />
                    <small>"Canonical identity is immutable after creation."</small>
                </label>
                <label>
                    <span>"Display name"</span>
                    <input required maxlength="120" prop:value=move || display_name.get()
                        on:input=move |event| display_name.set(event_target_value(&event)) />
                </label>
                <div class="form-actions">
                    <button class="button" type="submit" disabled=move || busy.get()>"Review update"</button>
                </div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! {
                <ReviewedPlanCard
                    plan=reviewed.plan
                    applying=busy.get()
                    on_apply=on_apply
                    on_cancel=Callback::new(move |()| pending.set(None))
                />
            })}
        </section>
    }
}

#[component]
fn ProjectInventory(client: ApiClient, organization: String, creation_only: bool) -> impl IntoView {
    let can_create = client.allows("registry.configure");
    let inventory_org = organization.clone();
    let inventory_client = client.clone();
    let inventory = LocalResource::new(move || {
        let client = inventory_client.clone();
        let org_slug = inventory_org.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListProjectsResponse, _, _, _>(
                    aos_proto_types::PROJECT_SERVICE_LIST_PROJECTS_PATH,
                    move |page_token| aos_proto_types::ListProjectsRequest {
                        org_slug: org_slug.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.projects, response.next_page_token),
                )
                .await
        }
    });
    let path = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let plan_client = client.clone();
    let plan_org = organization.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("project-create");
        let request = aos_proto_types::PlanCreateProjectRequest {
            org_slug: plan_org.clone(),
            path: path.get_untracked().trim().to_string(),
            name: name.get_untracked().trim().to_string(),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: String::new(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::PROJECT_SERVICE_PLAN_CREATE_PROJECT_PATH,
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

    let apply_client = client.clone();
    let destination = format!("/-/org/{organization}/projects");
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        let destination = destination.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ProjectResponse>(
                    aos_proto_types::PROJECT_SERVICE_CREATE_PROJECT_PATH,
                    &reviewed.project_apply(),
                )
                .await
            {
                Ok(_) => navigate(&destination),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="workflow-stack">
            {(!creation_only).then(|| view! { <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"Resource hierarchy"</p><h2>"Projects"</h2><p>"Projects create nested ownership paths without conflating storage or delivery."</p></div>{can_create.then(|| view! { <a class="button" href=format!("/-/org/{organization}/projects/new")>"Create project"</a> })}</div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading projects…"</p> }>
                    {move || {
                        let client = client.clone();
                        let organization = organization.clone();
                        Suspend::new(async move {
                            match inventory.await.as_ref() {
                                Ok(projects) if projects.is_empty() => view! { <p class="muted">"No projects yet. Registries may still live at the organization root."</p> }.into_any(),
                                Ok(projects) => view! { <table class="resource-table"><thead><tr><th>"Path"</th><th>"Name"</th><th>"Stable ID"</th><th><span class="visually-hidden">"Actions"</span></th></tr></thead><tbody>
                                    {projects.iter().cloned().map(|project| view! { <ProjectRow client=client.clone() project=project return_path=format!("/-/org/{organization}/projects")/> }).collect_view()}
                                </tbody></table> }.into_any(),
                                Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section> })}
            {creation_only.then(|| view! { <section class="panel editor-panel">
                <h2>"Create project"</h2>
                <form class="editor-form compact-form" on:submit=on_plan>
                    <label><span>"Materialized path"</span><input required placeholder="platform/runtime" prop:value=move || path.get() on:input=move |event| path.set(event_target_value(&event))/></label>
                    <label><span>"Display name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label>
                    <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div>
                </form>
                {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
                {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
            </section> })}
        </div>
    }
}

#[component]
fn ProjectRow(
    client: ApiClient,
    project: aos_proto_types::Project,
    return_path: String,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let org_slug = project.org_slug.clone();
    let path = project.path.clone();
    let resource_version = project.resource_version.clone();

    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("project-delete");
        let request = aos_proto_types::PlanDeleteProjectRequest {
            org_slug: org_slug.clone(),
            path: path.clone(),
            expected_resource_version: resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::PROJECT_SERVICE_PLAN_DELETE_PROJECT_PATH,
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
        let return_path = return_path.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                    aos_proto_types::PROJECT_SERVICE_DELETE_PROJECT_PATH,
                    &reviewed.project_apply(),
                )
                .await
            {
                Ok(_) => navigate(&return_path),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <tr>
            <td><code>{project.path}</code></td>
            <td>{project.name}</td>
            <td><code>{project.stable_id}</code></td>
            <td><button class="table-action" type="button" disabled=move || busy.get() on:click=on_plan>"Review delete"</button></td>
        </tr>
        {move || error.get().map(|detail| view! { <tr><td colspan="4"><InlineError detail=detail/></td></tr> })}
        {move || pending.get().map(|reviewed| view! {
            <tr><td colspan="4"><ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/></td></tr>
        })}
    }
}

#[component]
fn RegistryInventory(
    client: ApiClient,
    organization: String,
    creation_only: bool,
) -> impl IntoView {
    let can_create = client.allows("registry.configure");
    let inventory_client = client.clone();
    let prefix = format!("{organization}/");
    let inventory = LocalResource::new(move || {
        let client = inventory_client.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListRegistriesResponse, _, _, _>(
                    aos_proto_types::REGISTRY_SERVICE_LIST_REGISTRIES_PATH,
                    |page_token| aos_proto_types::ListRegistriesRequest {
                        page_size: 250,
                        page_token,
                    },
                    |response| (response.registries, response.next_page_token),
                )
                .await
        }
    });
    let project_path = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let visibility = RwSignal::new("private".to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let plan_client = client.clone();
    let plan_org = organization.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("registry-create");
        let request = aos_proto_types::PlanCreateRegistryRequest {
            org_slug: plan_org.clone(),
            project_path: project_path.get_untracked().trim().to_string(),
            name: name.get_untracked().trim().to_string(),
            visibility: visibility.get_untracked(),
            trust_keys: Vec::new(),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: String::new(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::REGISTRY_SERVICE_PLAN_CREATE_REGISTRY_PATH,
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
    let destination = format!("/-/org/{organization}/registries");
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        let destination = destination.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_CREATE_REGISTRY_PATH,
                    &reviewed.registry_apply(),
                )
                .await
            {
                Ok(_) => navigate(&destination),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="workflow-stack">
            {(!creation_only).then(|| view! { <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"Signed package surfaces"</p><h2>"Registries"</h2><p>"A registry owns signed releases and consumer configuration; placements and cache stacks are configured separately."</p></div>{can_create.then(|| view! { <a class="button" href=format!("/-/org/{organization}/registries/new")>"Create registry"</a> })}</div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading registries…"</p> }>{move || {
                    let prefix = prefix.clone();
                    Suspend::new(async move { match inventory.await.as_ref() {
                        Ok(all_registries) => { let registries = all_registries.iter().filter(|registry| registry.slug.starts_with(&prefix)).cloned().collect::<Vec<_>>(); if registries.is_empty() { view! { <p class="muted">"No registries in this organization."</p> }.into_any() } else { view! { <div class="resource-grid">{registries.into_iter().map(|registry| { let href = format!("/{}/-/settings", registry.slug); view! { <a class="resource-card" href=href><div><span class="resource-kind">{registry.visibility}</span><h3>{registry.name}</h3><code>{registry.slug}</code><StatusBadge state=registry.index_state.clone() positive=registry.index_state == "fresh"/></div><span class="card-arrow">"→"</span></a> } }).collect_view()}</div> }.into_any() } },
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    } })
                }}</Suspense>
            </section> })}
            {creation_only.then(|| view! { <section class="panel editor-panel"><h2>"Create registry"</h2><form class="editor-form compact-form" on:submit=on_plan>
                <label><span>"Project path"</span><input placeholder="Optional; for example platform/runtime" prop:value=move || project_path.get() on:input=move |event| project_path.set(event_target_value(&event))/></label>
                <label><span>"Registry name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label>
                <label><span>"Visibility"</span><select prop:value=move || visibility.get() on:change=move |event| visibility.set(event_target_value(&event))><option value="private">"Private"</option><option value="internal">"Internal"</option><option value="public">"Public"</option></select></label>
                <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div>
            </form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> })}
        </div>
    }
}

#[component]
fn OrganizationCacheInventory(
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
                            <CacheInventory client=client organization=organization owner_scope_key=owner_scope_key.clone() creation_only=creation_only/>
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
fn CacheInventory(
    client: ApiClient,
    organization: String,
    owner_scope_key: String,
    creation_only: bool,
) -> impl IntoView {
    let can_create = client.allows("registry.configure");
    let inventory_client = client.clone();
    let list_scope = owner_scope_key.clone();
    let inventory = LocalResource::new(move || {
        let client = inventory_client.clone();
        let owner_scope_key = list_scope.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListBinaryCachesResponse, _, _, _>(
                    aos_proto_types::BINARY_CACHE_SERVICE_LIST_BINARY_CACHES_PATH,
                    move |page_token| aos_proto_types::ListBinaryCachesRequest {
                        owner_scope_key: owner_scope_key.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.caches, response.next_page_token),
                )
                .await
        }
    });
    let cache_name = RwSignal::new(String::new());
    let display_name = RwSignal::new(String::new());
    let visibility = RwSignal::new("private".to_string());
    let compression = RwSignal::new("zstd".to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let plan_org = organization.clone();
    let plan_scope = owner_scope_key;
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("cache-create");
        let stable_id = format!("{}/{}", plan_org, cache_name.get_untracked().trim());
        let request = aos_proto_types::PlanBinaryCacheMutationRequest {
            stable_id: stable_id.clone(),
            desired: Some(aos_proto_types::BinaryCacheSpec {
                slug: stable_id,
                name: display_name.get_untracked().trim().to_string(),
                owner_scope_key: plan_scope.clone(),
                visibility: visibility.get_untracked(),
                nix_priority: 40,
                compression: compression.get_untracked(),
                want_mass_query: false,
            }),
            update_mask: vec![
                "slug".into(),
                "name".into(),
                "owner_scope_key".into(),
                "visibility".into(),
                "nix_priority".into(),
                "compression".into(),
                "want_mass_query".into(),
            ],
            expected_resource_version: String::new(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_CREATE_BINARY_CACHE_PATH,
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
    let apply_client = client;
    let destination = format!("/-/org/{organization}/caches");
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        let destination = destination.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::BinaryCacheResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_CREATE_BINARY_CACHE_PATH,
                    &reviewed.cache_apply(),
                )
                .await
            {
                Ok(_) => navigate(&destination),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <div class="workflow-stack">{(!creation_only).then(|| view! { <section class="panel resource-panel"><div class="section-heading"><div><p class="section-kicker">"Reusable object stores"</p><h2>"Binary caches"</h2><p>"Caches may stand alone or be shared by several registry consumer stacks and retention subscriptions."</p></div>{can_create.then(|| view! { <a class="button" href=format!("/-/org/{organization}/caches/new")>"Create binary cache"</a> })}</div><Suspense fallback=move || view! { <p class="loading-row">"Loading caches…"</p> }>{move || { let organization = organization.clone(); Suspend::new(async move { match inventory.await.as_ref() { Ok(caches) if caches.is_empty() => view! { <p class="muted">"No binary caches in this organization."</p> }.into_any(), Ok(caches) => view! { <div class="resource-grid">{caches.iter().cloned().map(|cache| { let href = format!("/-/org/{}/caches/{}", organization, cache.slug.rsplit('/').next().unwrap_or(&cache.slug)); view! { <a class="resource-card" href=href><div><span class="resource-kind">{cache.visibility}</span><h3>{cache.name}</h3><code>{cache.slug}</code><p class="resource-metric">{format!("{} objects · {} placements", cache.object_count, cache.placement_count)}</p></div><span class="card-arrow">"→"</span></a> } }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section> })}
    {creation_only.then(|| view! { <section class="panel editor-panel"><h2>"Create binary cache"</h2><form class="editor-form compact-form" on:submit=on_plan><label><span>"Cache slug"</span><input required placeholder="build" prop:value=move || cache_name.get() on:input=move |event| cache_name.set(event_target_value(&event))/></label><label><span>"Display name"</span><input required prop:value=move || display_name.get() on:input=move |event| display_name.set(event_target_value(&event))/></label><label><span>"Visibility"</span><select prop:value=move || visibility.get() on:change=move |event| visibility.set(event_target_value(&event))><option value="private">"Private"</option><option value="internal">"Internal"</option><option value="public">"Public"</option></select></label><label><span>"Compression"</span><select prop:value=move || compression.get() on:change=move |event| compression.set(event_target_value(&event))><option value="zstd">"Zstandard"</option><option value="xz">"XZ"</option><option value="none">"None"</option></select></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> })}</div> }
}

#[component]
fn RegistryOverview(client: ApiClient, slug: String) -> impl IntoView {
    let request_slug = slug.clone();
    let resource_client = client.clone();
    let resource = LocalResource::new(move || {
        let client = resource_client.clone();
        let slug = request_slug.clone();
        async move {
            client
                .call::<_, aos_proto_types::GetRegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_GET_REGISTRY_PATH,
                    &aos_proto_types::GetRegistryRequest { slug },
                )
                .await
        }
    });
    view! { <Suspense fallback=move || view! { <p class="loading-row">"Loading registry…"</p> }>{move || { let client = client.clone(); Suspend::new(async move { match resource.await.as_ref() { Ok(response) => match response.registry.clone() { Some(registry) => view! { <RegistryEditor client=client registry=registry/> }.into_any(), None => view! { <InlineError detail="The Hub omitted the registry.".to_string()/> }.into_any() }, Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense> }
}

#[component]
fn RegistryEditor(client: ApiClient, registry: aos_proto_types::Registry) -> impl IntoView {
    let visibility = RwSignal::new(registry.visibility.clone());
    let crawl_policy = RwSignal::new(registry.crawl_policy.clone());
    let llms = RwSignal::new(registry.llms_txt_body.clone());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let slug = registry.slug.clone();
    let version = registry.resource_version.clone();
    let plan_client = client.clone();
    let plan_slug = slug.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("registry-update");
        let request = aos_proto_types::PlanUpdateRegistryRequest {
            slug: plan_slug.clone(),
            visibility: visibility.get_untracked(),
            crawl_policy: crawl_policy.get_untracked(),
            llms_txt_body: llms.get_untracked(),
            trust_keys: registry.trust_keys.clone(),
            update_mask: vec![
                "visibility".into(),
                "crawl_policy".into(),
                "llms_txt_body".into(),
            ],
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::REGISTRY_SERVICE_PLAN_UPDATE_REGISTRY_PATH,
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
    let apply_client = client;
    let destination = format!("/{slug}/-/settings");
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        let destination = destination.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::RegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_UPDATE_REGISTRY_PATH,
                    &reviewed.registry_apply(),
                )
                .await
            {
                Ok(_) => navigate(&destination),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="panel editor-panel"><div class="resource-identity"><div><span>"Registry"</span><code>{slug}</code></div><div><span>"Index"</span><StatusBadge state=registry.index_state.clone() positive=registry.index_state == "fresh"/></div><div><span>"Version"</span><code>{registry.resource_version}</code></div></div><form class="editor-form" on:submit=on_plan><label><span>"Visibility"</span><select prop:value=move || visibility.get() on:change=move |event| visibility.set(event_target_value(&event))><option value="private">"Private"</option><option value="internal">"Internal"</option><option value="public">"Public"</option></select></label><label><span>"Crawler policy"</span><select prop:value=move || crawl_policy.get() on:change=move |event| crawl_policy.set(event_target_value(&event))><option value="allow_all">"Allow all"</option><option value="allow_no_ai">"Allow search; deny AI crawlers"</option><option value="deny_all">"Deny all"</option></select></label><label class="full-field"><span>"llms.txt body"</span><textarea rows="8" prop:value=move || llms.get() on:input=move |event| llms.set(event_target_value(&event))></textarea></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review update"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn CacheOverview(client: ApiClient, stable_id: String) -> impl IntoView {
    let request_id = stable_id.clone();
    let resource_client = client.clone();
    let resource = LocalResource::new(move || {
        let client = resource_client.clone();
        let cache_id = request_id.clone();
        async move {
            client
                .call::<_, aos_proto_types::BinaryCacheResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_BINARY_CACHE_PATH,
                    &aos_proto_types::GetBinaryCacheRequest { cache_id },
                )
                .await
        }
    });
    view! { <Suspense fallback=move || view! { <p class="loading-row">"Loading cache…"</p> }>{move || { let client = client.clone(); Suspend::new(async move { match resource.await.as_ref() { Ok(response) => match response.cache.clone() { Some(cache) => view! { <CacheEditor client=client cache=cache/> }.into_any(), None => view! { <InlineError detail="The Hub omitted the binary cache.".to_string()/> }.into_any() }, Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense> }
}

#[component]
fn CacheEditor(client: ApiClient, cache: aos_proto_types::BinaryCache) -> impl IntoView {
    let name = RwSignal::new(cache.name.clone());
    let visibility = RwSignal::new(cache.visibility.clone());
    let priority = RwSignal::new(cache.nix_priority.to_string());
    let compression = RwSignal::new(cache.compression.clone());
    let mass_query = RwSignal::new(cache.want_mass_query);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let stable_id = cache.stable_id.clone();
    let version = cache.resource_version.clone();
    let plan_client = client.clone();
    let plan_id = stable_id.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let parsed_priority = match priority.get_untracked().parse::<u32>() {
            Ok(value) => value,
            Err(_) => {
                error.set(Some("Nix priority must be an unsigned integer".into()));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("cache-update");
        let request = aos_proto_types::PlanBinaryCacheMutationRequest {
            stable_id: plan_id.clone(),
            desired: Some(aos_proto_types::BinaryCacheSpec {
                slug: String::new(),
                name: name.get_untracked().trim().to_string(),
                owner_scope_key: String::new(),
                visibility: visibility.get_untracked(),
                nix_priority: parsed_priority,
                compression: compression.get_untracked(),
                want_mass_query: mass_query.get_untracked(),
            }),
            update_mask: vec![
                "name".into(),
                "visibility".into(),
                "nix_priority".into(),
                "compression".into(),
                "want_mass_query".into(),
            ],
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_PLAN_UPDATE_BINARY_CACHE_PATH,
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
    let apply_client = client;
    let destination = cache_path(&stable_id);
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        let destination = destination.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::BinaryCacheResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_UPDATE_BINARY_CACHE_PATH,
                    &reviewed.cache_apply(),
                )
                .await
            {
                Ok(_) => navigate(&destination),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="panel editor-panel"><div class="resource-identity"><div><span>"Cache"</span><code>{cache.slug}</code></div><div><span>"Usage"</span><strong>{format_bytes(cache.used_bytes)}</strong></div><div><span>"Objects"</span><strong>{cache.object_count}</strong></div><div><span>"Roots"</span><strong>{cache.retention_root_count}</strong></div></div><form class="editor-form" on:submit=on_plan><label><span>"Display name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label><label><span>"Visibility"</span><select prop:value=move || visibility.get() on:change=move |event| visibility.set(event_target_value(&event))><option value="private">"Private"</option><option value="internal">"Internal"</option><option value="public">"Public"</option></select></label><label><span>"Nix priority"</span><input type="number" min="0" prop:value=move || priority.get() on:input=move |event| priority.set(event_target_value(&event))/></label><label><span>"Compression"</span><select prop:value=move || compression.get() on:change=move |event| compression.set(event_target_value(&event))><option value="zstd">"Zstandard"</option><option value="xz">"XZ"</option><option value="none">"None"</option></select></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || mass_query.get() on:change=move |event| mass_query.set(event_target_checked(&event))/><span>"Advertise WantMassQuery"</span></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review update"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn OrganizationDanger(client: ApiClient, slug: String) -> impl IntoView {
    let get_client = client.clone();
    let request_slug = slug.clone();
    let resource = LocalResource::new(move || {
        let client = get_client.clone();
        let slug = request_slug.clone();
        async move {
            client
                .call::<_, aos_proto_types::OrganizationResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_GET_ORGANIZATION_PATH,
                    &aos_proto_types::GetOrganizationRequest { slug },
                )
                .await
        }
    });
    view! { <Suspense fallback=move || view! { <p class="loading-row">"Loading deletion preconditions…"</p> }>{move || { let client = client.clone(); Suspend::new(async move { match resource.await.as_ref() { Ok(response) => match response.organization.clone() { Some(organization) => view! { <OrganizationDelete client=client organization=organization/> }.into_any(), None => view! { <InlineError detail="The Hub omitted the organization.".to_string()/> }.into_any() }, Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense> }
}

#[component]
fn OrganizationDelete(
    client: ApiClient,
    organization: aos_proto_types::Organization,
) -> impl IntoView {
    let confirmation = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let slug = organization.slug.clone();
    let version = organization.resource_version.clone();
    let plan_client = client.clone();
    let plan_slug = slug.clone();
    let required = slug.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        if confirmation.get_untracked() != required {
            error.set(Some("Type the exact organization slug to continue".into()));
            return;
        }
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("organization-delete");
        let request = aos_proto_types::PlanDeleteOrganizationRequest {
            slug: plan_slug.clone(),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_PLAN_DELETE_ORGANIZATION_PATH,
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
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_DELETE_ORGANIZATION_PATH,
                    &reviewed.organization_apply(),
                )
                .await
            {
                Ok(_) => navigate("/-/orgs"),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="panel danger-panel"><p class="section-kicker">"Destructive operation"</p><h2>"Delete organization"</h2><p>"The plan will fail closed while owned projects, registries, caches, grants, or other resources remain."</p><form class="editor-form" on:submit=on_plan><label><span>{format!("Type `{slug}` to continue")}</span><input autocomplete="off" prop:value=move || confirmation.get() on:input=move |event| confirmation.set(event_target_value(&event))/></label><div class="form-actions"><button class="danger-button" type="submit" disabled=move || busy.get()>"Review deletion"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn RegistryDanger(client: ApiClient, slug: String) -> impl IntoView {
    let get_client = client.clone();
    let request_slug = slug.clone();
    let resource = LocalResource::new(move || {
        let client = get_client.clone();
        let slug = request_slug.clone();
        async move {
            client
                .call::<_, aos_proto_types::GetRegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_GET_REGISTRY_PATH,
                    &aos_proto_types::GetRegistryRequest { slug },
                )
                .await
        }
    });
    view! { <Suspense fallback=move || view! { <p class="loading-row">"Loading deletion preconditions…"</p> }>{move || { let client = client.clone(); Suspend::new(async move { match resource.await.as_ref() { Ok(response) => match response.registry.clone() { Some(registry) => view! { <TopologyDelete client=client kind="registry" stable_id=registry.stable_id resource_version=registry.resource_version plan_path=aos_proto_types::REGISTRY_SERVICE_PLAN_DELETE_REGISTRY_PATH apply_path=aos_proto_types::REGISTRY_SERVICE_DELETE_REGISTRY_PATH return_path=format!("/-/org/{}/registries", registry.slug.split('/').next().unwrap_or_default())/> }.into_any(), None => view! { <InlineError detail="The Hub omitted the registry.".to_string()/> }.into_any() }, Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense> }
}

#[component]
fn CacheDanger(client: ApiClient, stable_id: String) -> impl IntoView {
    let get_client = client.clone();
    let request_id = stable_id.clone();
    let resource = LocalResource::new(move || {
        let client = get_client.clone();
        let cache_id = request_id.clone();
        async move {
            client
                .call::<_, aos_proto_types::BinaryCacheResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_BINARY_CACHE_PATH,
                    &aos_proto_types::GetBinaryCacheRequest { cache_id },
                )
                .await
        }
    });
    view! { <Suspense fallback=move || view! { <p class="loading-row">"Loading deletion preconditions…"</p> }>{move || { let client = client.clone(); Suspend::new(async move { match resource.await.as_ref() { Ok(response) => match response.cache.clone() { Some(cache) => view! { <TopologyDelete client=client kind="binary cache" stable_id=cache.stable_id resource_version=cache.resource_version plan_path=aos_proto_types::BINARY_CACHE_SERVICE_PLAN_DELETE_BINARY_CACHE_PATH apply_path=aos_proto_types::BINARY_CACHE_SERVICE_DELETE_BINARY_CACHE_PATH return_path=format!("/-/org/{}/caches", cache.slug.split('/').next().unwrap_or_default())/> }.into_any(), None => view! { <InlineError detail="The Hub omitted the binary cache.".to_string()/> }.into_any() }, Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense> }
}

#[component]
fn TopologyDelete(
    client: ApiClient,
    kind: &'static str,
    stable_id: String,
    resource_version: String,
    plan_path: &'static str,
    apply_path: &'static str,
    return_path: String,
) -> impl IntoView {
    let confirmation = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let required = stable_id.clone();
    let request_id = stable_id.clone();
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        if confirmation.get_untracked() != required {
            error.set(Some(format!("Type the exact {kind} stable ID to continue")));
            return;
        }
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("topology-delete");
        let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
            stable_id: request_id.clone(),
            expected_resource_version: Some(resource_version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(plan_path, &request)
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
        let return_path = return_path.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                    apply_path,
                    &reviewed.delete_apply(),
                )
                .await
            {
                Ok(_) => navigate(&return_path),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="panel danger-panel"><p class="section-kicker">"Destructive operation"</p><h2>{format!("Delete {kind}")}</h2><p>"The server plan enumerates dependent placements, routes, grants, integrations, and retention roots. No dependent resource is silently removed."</p><form class="editor-form" on:submit=on_plan><label><span>{format!("Type `{stable_id}` to continue")}</span><input autocomplete="off" prop:value=move || confirmation.get() on:input=move |event| confirmation.set(event_target_value(&event))/></label><div class="form-actions"><button class="danger-button" type="submit" disabled=move || busy.get()>"Review deletion"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

fn navigate(path: &str) {
    if let Some(window) = leptos::web_sys::window() {
        let _ = window.location().set_href(path);
    }
}

fn cache_path(stable_id: &str) -> String {
    let mut segments = stable_id.splitn(2, '/');
    let organization = segments.next().unwrap_or_default();
    let cache = segments.next().unwrap_or_default();
    format!("/-/org/{organization}/caches/{cache}")
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
