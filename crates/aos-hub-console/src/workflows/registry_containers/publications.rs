//! Verified container-publication history.

use leptos::prelude::*;

use crate::components::{HashValue, InlineError, StatusBadge};
use crate::transport::ApiClient;

use super::display_or;

/// Renders complete publication transaction records for one repository.
#[component]
pub(super) fn ContainerPublications(
    client: ApiClient,
    registry: String,
    repository: String,
) -> impl IntoView {
    let list_client = client;
    let publications = LocalResource::new(move || {
        let client = list_client.clone();
        let registry = registry.clone();
        let repository = repository.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListContainerPublicationsResponse, _, _, _>(
                    aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_PUBLICATIONS_PATH,
                    move |page_token| aos_proto_types::ListContainerPublicationsRequest {
                        registry: registry.clone(),
                        repository: repository.clone(),
                        state: String::new(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.publications, response.next_page_token),
                )
                .await
        }
    });
    view! {
        <section class="panel resource-panel"><div class="section-heading"><div><p class="section-kicker">"Verified admission transactions"</p><h2>"Publication history"</h2></div></div><Suspense fallback=move || view! { <p class="loading-row">"Loading container publications…"</p> }>{move || Suspend::new(async move { match publications.await.as_ref() { Ok(values) if values.is_empty() => view! { <p class="muted">"No container publications have been recorded."</p> }.into_any(), Ok(values) => view! { <div class="binding-list">{values.iter().cloned().map(|publication| view! { <PublicationCard publication=publication/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } })}</Suspense></section>
    }
}

#[component]
fn PublicationCard(publication: aos_proto_types::ContainerPublication) -> impl IntoView {
    let positive = publication.state == "committed";
    view! {
        <details class="binding-card"><summary><div><span class="resource-kind">{display_or(&publication.source_kind, "container")}</span><h3>{display_or(&publication.target_tag, "digest publication")}</h3><code>{publication.publication_id.clone()}</code></div><StatusBadge state=publication.state.clone() positive=positive/></summary><div class="binding-details"><div class="resource-identity"><div><span>"Root digest"</span><HashValue value=publication.root_digest/></div><div><span>"Catalog"</span><HashValue value=publication.catalog_digest/></div><div><span>"Verified release root"</span><HashValue value=publication.verified_release_root/></div><div><span>"Topology"</span><HashValue value=publication.topology_digest/></div><div><span>"Placements"</span><strong>{publication.required_placement_count}</strong></div><div><span>"Version"</span><code>{publication.resource_version}</code></div><div><span>"Created"</span><strong>{publication.created_at}</strong></div><div><span>"Committed"</span><strong>{if publication.committed_at == 0 { "not committed".to_string() } else { publication.committed_at.to_string() }}</strong></div></div></div></details>
    }
}
