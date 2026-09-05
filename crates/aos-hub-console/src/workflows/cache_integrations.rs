//! Cache-side registry integration discovery workflows.
//!
//! A cache remains independently owned even when it serves several registries.
//! This page shows those reverse relationships. Registry-owned ordering and
//! signing are edited by the consumer-cache stack workflow.

use leptos::prelude::*;

use crate::components::{InlineError, StatusBadge};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::access_tokens::{AccessTokenSurface, AccessTokenWorkflow};
use super::cache_gc::CacheGcWorkflow;
use super::cache_integration_preview::CacheIntegrationPreview;
use super::cache_objects::CacheObjects;
use super::cache_population::CachePopulation;
use super::cache_retention::CacheRetentionWorkflow;
use super::cache_stack::RegistryCacheStack;
use super::operations::{OperationSurface, OperationsWorkflow};
use super::organization_activity::OrganizationActivity;
use super::registry_configuration::RegistryConfiguration;
use super::registry_containers::RegistryContainers;
use super::registry_mirror::RegistryMirrorWorkflow;
use super::registry_publication::RegistryPublicationWorkflow;
use super::resource_access::{ResourceAccessSurface, ResourceAccessWorkflow};
use super::signing_keys::{SigningKeyTarget, SigningKeyWorkflow};

/// Renders registry/cache integration pages and delegates unrelated routes.
#[component]
pub(super) fn CacheIntegrationWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "tokens") => view! {
            <AccessTokenWorkflow client=client surface=AccessTokenSurface::Instance/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "tokens") => view! {
            <AccessTokenWorkflow
                client=client
                surface=AccessTokenSurface::Organization(slug.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Instance, "operations") => view! {
            <OperationsWorkflow client=client surface=OperationSurface::Instance/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "operations") => view! {
            <OperationsWorkflow
                client=client
                surface=OperationSurface::Organization(slug.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "operations") => view! {
            <OperationsWorkflow
                client=client
                surface=OperationSurface::Registry(path.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "operations") => view! {
            <OperationsWorkflow
                client=client
                surface=OperationSurface::Cache(path.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "caches") => view! {
            <RegistryCacheStack client=client registry_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "access") => view! {
            <ResourceAccessWorkflow
                client=client
                surface=ResourceAccessSurface::Registry(path.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "access") => view! {
            <ResourceAccessWorkflow
                client=client
                surface=ResourceAccessSurface::Cache(path.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "publish-history") => view! {
            <RegistryPublicationWorkflow client=client registry_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "containers") => view! {
            <RegistryContainers client=client registry_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Registry { path }, page @ ("configuration" | "changes")) => view! {
            <RegistryConfiguration client=client registry_id=path.clone() page=page/>
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "mirror") => view! {
            <RegistryMirrorWorkflow client=client registry_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "tokens") => view! {
            <AccessTokenWorkflow
                client=client
                surface=AccessTokenSurface::Registry(path.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "tokens") => view! {
            <AccessTokenWorkflow
                client=client
                surface=AccessTokenSurface::Cache(path.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "signing") => view! {
            <SigningKeyWorkflow
                client=client
                target=SigningKeyTarget::Organization(slug.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, page @ ("webhooks" | "audit")) => view! {
            <OrganizationActivity
                client=client
                organization=slug.clone()
                page=page
            />
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "signing") => view! {
            <SigningKeyWorkflow
                client=client
                target=SigningKeyTarget::Registry(path.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "signing") => view! {
            <SigningKeyWorkflow
                client=client
                target=SigningKeyTarget::Cache(path.clone())
            />
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "integrations") => view! {
            <CacheIntegrations client=client cache_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "objects") => view! {
            <CacheObjects client=client cache_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "retention") => view! {
            <CacheRetentionWorkflow client=client cache_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Cache { path }, "gc") => view! {
            <CacheGcWorkflow client=client cache_id=path.clone()/>
        }
        .into_any(),
        _ => unreachable!(
            "closed console route has no workflow adapter: {}",
            route.page.workflow
        ),
    }
}

#[component]
fn CacheIntegrations(client: ApiClient, cache_id: String) -> impl IntoView {
    let task = RwSignal::new("overview".to_string());
    let read_client = client.clone();
    let read_cache_id = cache_id.clone();
    let integrations = LocalResource::new(move || {
        let client = read_client.clone();
        let cache_id = read_cache_id.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListCacheIntegrationsResponse, _, _, _>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_LIST_CACHE_REGISTRY_INTEGRATIONS_PATH,
                    move |page_token| aos_proto_types::ListCacheRegistryIntegrationsRequest {
                        cache_id: cache_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.integrations, response.next_page_token),
                )
                .await
        }
    });
    let task_client = client.clone();
    let task_cache_id = cache_id.clone();
    let retention_href = cache_settings_href(&cache_id, "retention");

    view! {
        <div class="workflow-stack">
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Choose an outcome"</p><h2>"Connect this cache"</h2><p>"Client use, proactive population, and retention are separate settings. This page only shows relationships owned by this cache; registry cache ordering and signing stay with the registry."</p></div></div>
            <div class="resource-grid">
                <article class="resource-card"><div><span class="resource-kind">"Client configuration"</span><h3>"Use this cache for installs"</h3><p>"Add it to a registry's signed, ordered consumer cache stack. The registry owns that setting."</p></div></article>
                <button class="resource-card" type="button" on:click=move |_| task.set("populate".to_string())><div><span class="resource-kind">"Availability"</span><h3>"Populate this cache"</h3><p>"Copy and verify a registry's objects here without changing client configuration or retention."</p></div><span class="card-arrow">"→"</span></button>
                <a class="resource-card" href=retention_href><div><span class="resource-kind">"Garbage collection"</span><h3>"Keep registry objects"</h3><p>"Create retention roots from signed catalogs, channels, or releases."</p></div><span class="card-arrow">"→"</span></a>
            </div>
            <div class="compact-form">
                <label><span>"Task"</span><select prop:value=move || task.get() on:change=move |event| task.set(event_target_value(&event))><option value="overview">"View current relationships"</option><option value="populate">"Configure population and coverage"</option><option value="preview">"Advanced cross-resource preview"</option></select></label>
            </div>
        </section>
        {move || {
            let client = task_client.clone();
            let cache_id = task_cache_id.clone();
            match task.get().as_str() {
                "populate" => view! { <CachePopulation client=client cache_id=cache_id/> }.into_any(),
                "preview" => view! { <CacheIntegrationPreview client=client cache_id=cache_id/> }.into_any(),
                _ => ().into_any(),
            }
        }}
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Reverse topology"</p>
                    <h2>"Registry integrations"</h2>
                    <p>
                        "One cache may serve many registries. Publication, retention, and population are independent relationships."
                    </p>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading integrations…"</p> }>
                {move || Suspend::new(async move {
                    match integrations.await.as_ref() {
                        Ok(integrations) if integrations.is_empty() => view! {
                            <div class="empty-state"><h3>"No registry relationships"</h3><p>"Connect a registry only when it needs client publication, population, or retention roots from this cache."</p></div>
                        }
                        .into_any(),
                        Ok(integrations) => view! {
                            <div class="binding-list">
                                {integrations
                                    .iter()
                                    .cloned()
                                    .map(|integration| view! {
                                        <IntegrationCard integration=integration/>
                                    })
                                    .collect_view()}
                            </div>
                        }
                        .into_any(),
                        Err(failure) => view! {
                            <InlineError detail=failure.to_string()/>
                        }
                        .into_any(),
                    }
                })}
            </Suspense>
        </section>
        </div>
    }
}

#[component]
fn IntegrationCard(integration: aos_proto_types::CacheIntegration) -> impl IntoView {
    let published = !integration.publications.is_empty();
    let retained = integration.retention.is_some();
    let populated = integration.population.is_some();
    let registry_href = format!("/{}/-/settings/caches", integration.registry_id);

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <a href=registry_href><strong>{integration.registry_id}</strong></a>
                    <span>{integration.cache_id}</span>
                </div>
                <StatusBadge
                    state=if published { "published" } else { "not published" }.to_string()
                    positive=published
                />
            </div>
            <div class="resource-identity">
                <div>
                    <span>"Client stack entries"</span>
                    <strong>{integration.publications.len()}</strong>
                </div>
                <div>
                    <span>"Retention roots"</span>
                    <strong>{if retained { "configured" } else { "none" }}</strong>
                </div>
                <div>
                    <span>"Population"</span>
                    <strong>{if populated { "configured" } else { "none" }}</strong>
                </div>
            </div>
        </article>
    }
}

fn cache_settings_href(cache_id: &str, page: &str) -> String {
    match cache_id.split_once('/') {
        Some((organization, cache)) => format!("/-/org/{organization}/caches/{cache}/{page}"),
        None => format!("/-/caches/{cache_id}/{page}"),
    }
}
