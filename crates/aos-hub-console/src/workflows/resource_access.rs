//! Resource-local identity and access topology.
//!
//! Registry and cache access pages explain the immutable authorization scope,
//! infrastructure-owner scope, visibility posture, and the dedicated editors
//! that manage memberships, credentials, and signing trust. Delivery-route
//! client access remains a route property and is intentionally not duplicated
//! here.

use leptos::prelude::*;

use crate::components::{InlineError, StatusBadge};
use crate::transport::ApiClient;

/// One resource access surface resolved from a canonical console route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ResourceAccessSurface {
    /// Registry path locator.
    Registry(String),
    /// Organization and cache route locators.
    Cache { organization: String, cache: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccessContext {
    kind: &'static str,
    label: String,
    visibility: String,
    authorization_scope: String,
    owner_scope: String,
    overview_href: String,
    signing_href: String,
    tokens_href: String,
    members_href: String,
}

/// Renders resource-local access ownership and links to single-purpose editors.
#[component]
pub(super) fn ResourceAccessWorkflow(
    client: ApiClient,
    surface: ResourceAccessSurface,
) -> impl IntoView {
    let context_client = client.clone();
    let context = LocalResource::new(move || {
        let client = context_client.clone();
        let surface = surface.clone();
        async move { resolve_access_context(&client, surface).await }
    });

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Resolving access topology…"</p> }>
            {move || Suspend::new(async move {
                match context.await.as_ref() {
                    Ok(context) => view! { <AccessOverview context=context.clone()/> }.into_any(),
                    Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                }
            })}
        </Suspense>
    }
}

async fn resolve_access_context(
    client: &ApiClient,
    surface: ResourceAccessSurface,
) -> Result<AccessContext, String> {
    let context = match surface {
        ResourceAccessSurface::Registry(path) => {
            let response = client
                .call::<_, aos_proto_types::GetRegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_GET_REGISTRY_PATH,
                    &aos_proto_types::GetRegistryRequest { slug: path.clone() },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let registry = response
                .registry
                .ok_or_else(|| "the Hub omitted the registry".to_string())?;
            let organization = path
                .split('/')
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "the registry path omitted its organization".to_string())?;
            let base = format!("/{path}/-/settings");
            AccessContext {
                kind: "Registry",
                label: registry.slug,
                visibility: registry.visibility,
                authorization_scope: registry.authorization_scope_key,
                owner_scope: registry.owner_scope_key,
                overview_href: base.clone(),
                signing_href: format!("{base}/signing-keys"),
                tokens_href: format!("{base}/tokens"),
                members_href: format!("/-/org/{organization}/members"),
            }
        }
        ResourceAccessSurface::Cache {
            organization,
            cache: cache_name,
        } => {
            let cache_id = format!("{organization}/{cache_name}");
            let response = client
                .call::<_, aos_proto_types::BinaryCacheResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_BINARY_CACHE_PATH,
                    &aos_proto_types::GetBinaryCacheRequest {
                        cache_id: cache_id.clone(),
                    },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let cache = response
                .cache
                .ok_or_else(|| "the Hub omitted the binary cache".to_string())?;
            let base = format!("/-/org/{organization}/caches/{cache_name}");
            AccessContext {
                kind: "Binary cache",
                label: cache_id,
                visibility: cache.visibility,
                authorization_scope: cache.authorization_scope_key,
                owner_scope: cache.owner_scope_key,
                overview_href: base.clone(),
                signing_href: format!("{base}/signing-keys"),
                tokens_href: format!("{base}/tokens"),
                members_href: format!("/-/org/{organization}/members"),
            }
        }
    };
    if context.authorization_scope.is_empty() || context.owner_scope.is_empty() {
        return Err("the Hub omitted immutable access-scope metadata".to_string());
    }
    Ok(context)
}

#[component]
fn AccessOverview(context: AccessContext) -> impl IntoView {
    let public = context.visibility == "public";
    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">{context.kind}</p>
                        <h2>"Identity & access"</h2>
                        <p>"Resource IAM, credentials, signing trust, and client delivery policy remain explicit layers."</p>
                    </div>
                    <StatusBadge state=context.visibility.clone() positive=public/>
                </div>
                <div class="resource-identity">
                    <div><span>"Resource"</span><strong>{context.label}</strong></div>
                    <div><span>"Authorization scope"</span><code>{context.authorization_scope}</code></div>
                    <div><span>"Infrastructure owner"</span><code>{context.owner_scope}</code></div>
                </div>
                <p class="muted">
                    "Visibility is resource policy. Human and service-account grants are memberships. API credentials are scoped tokens. Client-facing HTTP authorization is configured on each simultaneous delivery route."
                </p>
            </section>
            <section class="resource-grid">
                <a class="resource-card" href=context.members_href>
                    <div><span class="resource-kind">"IAM"</span><h3>"Memberships"</h3><p>"Grant a user or service account a role on an exact immutable scope."</p></div>
                </a>
                <a class="resource-card" href=context.tokens_href>
                    <div><span class="resource-kind">"Credentials"</span><h3>"Access tokens"</h3><p>"Issue and retire scope-owned API credentials."</p></div>
                </a>
                <a class="resource-card" href=context.signing_href>
                    <div><span class="resource-kind">"Trust"</span><h3>"Signing keys"</h3><p>"Inspect immutable generations and exact consumer usage."</p></div>
                </a>
                <a class="resource-card" href=context.overview_href>
                    <div><span class="resource-kind">"Policy"</span><h3>"Visibility"</h3><p>"Edit the resource visibility and other identity policy."</p></div>
                </a>
            </section>
        </div>
    }
}
