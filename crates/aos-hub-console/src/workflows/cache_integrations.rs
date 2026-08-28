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
use super::registry_catalog::RegistryCatalog;
use super::registry_configuration::RegistryConfiguration;
use super::registry_containers::RegistryContainers;
use super::registry_images::RegistryImages;
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
        (ConsoleScope::Registry { path }, "images") => view! {
            <RegistryImages client=client registry_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Registry { path }, "containers") => view! {
            <RegistryContainers client=client registry_id=path.clone()/>
        }
        .into_any(),
        (ConsoleScope::Registry { path }, page @ ("packages" | "channels")) => view! {
            <RegistryCatalog client=client registry_id=path.clone() page=page/>
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

    view! {
        <div class="workflow-stack">
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
                            <p class="muted">"This cache has no registry integrations."</p>
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
        <CacheIntegrationPreview client=client.clone() cache_id=cache_id.clone()/>
        <CachePopulation client=client cache_id=cache_id/>
        </div>
    }
}

#[component]
fn IntegrationCard(integration: aos_proto_types::CacheIntegration) -> impl IntoView {
    let published = !integration.publications.is_empty();
    let retained = integration.retention.is_some();
    let populated = integration.population.is_some();

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{integration.registry_id}</strong>
                    <span>{integration.cache_id}</span>
                </div>
                <StatusBadge
                    state=if published { "published" } else { "not published" }.to_string()
                    positive=published
                />
            </div>
            <div class="resource-identity">
                <div>
                    <span>"Consumer entries"</span>
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
