//! Immutable manifest, platform, layer, referrer, and provenance inspection.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HashValue, InlineError, StatusBadge};
use crate::transport::{ApiClient, TransportError};

use super::{display_or, format_bytes};

#[derive(Clone, Default)]
struct GraphView {
    manifest: aos_proto_types::ContainerManifest,
    platforms: Vec<aos_proto_types::ContainerPlatform>,
    layers: Vec<aos_proto_types::ContainerLayer>,
    referrers: Vec<aos_proto_types::ContainerReferrer>,
    provenance: Option<aos_proto_types::ContainerProvenance>,
}

/// Renders one immutable OCI graph selected by root digest.
#[component]
pub(super) fn ContainerGraphInspector(
    client: ApiClient,
    registry: String,
    repository: String,
) -> impl IntoView {
    let digest = RwSignal::new(String::new());
    let release = RwSignal::new(String::new());
    let graph = RwSignal::new(None::<GraphView>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let root_digest = digest.get_untracked().trim().to_string();
        let exact_release = release.get_untracked().trim().to_string();
        if root_digest.is_empty() {
            error.set(Some("Root digest is required.".to_string()));
            return;
        }
        let client = client.clone();
        let registry = registry.clone();
        let repository = repository.clone();
        busy.set(true);
        error.set(None);
        graph.set(None);
        spawn_local(async move {
            match load_graph(
                &client,
                &registry,
                &repository,
                &root_digest,
                &exact_release,
            )
            .await
            {
                Ok(value) => graph.set(Some(value)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Immutable graph"</p><h2>"Manifest, platforms & evidence"</h2><p>"Enter a digest from a tag or publication to traverse normalized OCI metadata and verified AOS provenance."</p></div></div>
            <form class="editor-form" on:submit=on_submit>
                <label><span>"Root digest"</span><input required placeholder="sha256:…" prop:value=move || digest.get() on:input=move |event| digest.set(event_target_value(&event))/></label>
                <label><span>"Exact signed release (for provenance)"</span><input placeholder="2026.08.1" prop:value=move || release.get() on:input=move |event| release.set(event_target_value(&event))/></label>
                <div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get()>"Inspect graph"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || graph.get().map(|value| view! { <GraphDetail graph=value/> })}
        </section>
    }
}

async fn load_graph(
    client: &ApiClient,
    registry: &str,
    repository: &str,
    root_digest: &str,
    release: &str,
) -> Result<GraphView, String> {
    let manifest = client
        .call::<_, aos_proto_types::ContainerManifestResponse>(
            aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_MANIFEST_PATH,
            &aos_proto_types::GetContainerManifestRequest {
                registry: registry.to_string(),
                repository: repository.to_string(),
                digest: root_digest.to_string(),
            },
        )
        .await
        .map_err(|failure| failure.to_string())?
        .manifest
        .ok_or_else(|| "The Hub omitted the manifest.".to_string())?;

    let platforms = client
        .collect_pages::<_, aos_proto_types::ListContainerPlatformsResponse, _, _, _>(
            aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_PLATFORMS_PATH,
            |page_token| aos_proto_types::ListContainerPlatformsRequest {
                registry: registry.to_string(),
                repository: repository.to_string(),
                root_digest: root_digest.to_string(),
                page_size: 100,
                page_token,
            },
            |response| (response.platforms, response.next_page_token),
        )
        .await
        .map_err(|failure| failure.to_string())?;

    let layer_manifests = if platforms.is_empty() {
        vec![root_digest.to_string()]
    } else {
        platforms
            .iter()
            .map(|platform| platform.manifest_digest.clone())
            .collect()
    };
    let mut layers = Vec::new();
    for manifest_digest in layer_manifests {
        let mut manifest_layers = client
            .collect_pages::<_, aos_proto_types::ListContainerLayersResponse, _, _, _>(
                aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_LAYERS_PATH,
                |page_token| aos_proto_types::ListContainerLayersRequest {
                    registry: registry.to_string(),
                    repository: repository.to_string(),
                    manifest_digest: manifest_digest.clone(),
                    page_size: 100,
                    page_token,
                    root_digest: root_digest.to_string(),
                },
                |response| (response.layers, response.next_page_token),
            )
            .await
            .map_err(|failure| failure.to_string())?;
        layers.append(&mut manifest_layers);
    }

    let referrers = client
        .collect_pages::<_, aos_proto_types::ListContainerReferrersResponse, _, _, _>(
            aos_proto_types::CONTAINER_SERVICE_LIST_CONTAINER_REFERRERS_PATH,
            |page_token| aos_proto_types::ListContainerReferrersRequest {
                registry: registry.to_string(),
                repository: repository.to_string(),
                subject_digest: root_digest.to_string(),
                artifact_type: String::new(),
                page_size: 100,
                page_token,
            },
            |response| (response.referrers, response.next_page_token),
        )
        .await
        .map_err(|failure| failure.to_string())?;

    let provenance = if release.is_empty() {
        None
    } else {
        match client
            .call::<_, aos_proto_types::ContainerProvenanceResponse>(
                aos_proto_types::CONTAINER_SERVICE_GET_CONTAINER_PROVENANCE_PATH,
                &aos_proto_types::GetContainerProvenanceRequest {
                    registry: registry.to_string(),
                    repository: repository.to_string(),
                    root_digest: root_digest.to_string(),
                    release: release.to_string(),
                },
            )
            .await
        {
            Ok(response) => response.provenance,
            Err(TransportError::Http { status: 404, .. }) => None,
            Err(failure) => return Err(failure.to_string()),
        }
    };

    Ok(GraphView {
        manifest,
        platforms,
        layers,
        referrers,
        provenance,
    })
}

#[component]
fn GraphDetail(graph: GraphView) -> impl IntoView {
    let manifest = graph.manifest;
    view! {
        <div class="workflow-stack container-graph">
            <article class="revision-card"><div class="compact-list-row"><div><strong>"Manifest"</strong><span>{manifest.media_type}</span></div><HashValue value=manifest.digest/></div><div class="resource-identity"><div><span>"Bytes"</span><strong>{format_bytes(manifest.byte_size)}</strong></div><div><span>"Artifact type"</span><code>{display_or(&manifest.artifact_type, "image")}</code></div><div><span>"Config"</span><HashValue value=manifest.config_digest/></div><div><span>"Layers"</span><strong>{manifest.layer_count}</strong></div><div><span>"Children"</span><strong>{manifest.child_count}</strong></div></div>{(!manifest.annotations_json.is_empty()).then(|| view! { <details><summary>"Manifest annotations"</summary><pre class="json-view">{manifest.annotations_json}</pre></details> })}</article>
            <section class="subworkflow"><h3>"Platforms"</h3>{if graph.platforms.is_empty() { view! { <p class="muted">"This manifest has no indexed platform children."</p> }.into_any() } else { view! { <div class="binding-list">{graph.platforms.into_iter().map(|platform| view! { <PlatformCard platform=platform/> }).collect_view()}</div> }.into_any() }}</section>
            <section class="subworkflow"><h3>"Layers"</h3>{if graph.layers.is_empty() { view! { <p class="muted">"No layers are indexed for the selected manifest."</p> }.into_any() } else { view! { <div class="compact-list">{graph.layers.into_iter().map(|layer| view! { <LayerRow layer=layer/> }).collect_view()}</div> }.into_any() }}</section>
            <section class="subworkflow"><h3>"Referrers"</h3>{if graph.referrers.is_empty() { view! { <p class="muted">"No attestations or artifacts refer to this digest."</p> }.into_any() } else { view! { <div class="compact-list">{graph.referrers.into_iter().map(|referrer| view! { <ReferrerRow referrer=referrer/> }).collect_view()}</div> }.into_any() }}</section>
            {graph.provenance.map(|provenance| view! { <ProvenanceDetail provenance=provenance/> })}
        </div>
    }
}

#[component]
fn PlatformCard(platform: aos_proto_types::ContainerPlatform) -> impl IntoView {
    let label = format!(
        "{}/{}{}",
        platform.operating_system,
        platform.architecture,
        if platform.variant.is_empty() {
            String::new()
        } else {
            format!("/{}", platform.variant)
        }
    );
    let os_features = platform.os_features.join(", ");
    view! { <article class="revision-card"><div class="compact-list-row"><div><strong>{label}</strong><span>{display_or(&platform.aos_system, "unmapped AOS system")}</span></div><HashValue value=platform.manifest_digest/></div><div class="resource-identity"><div><span>"Config"</span><HashValue value=platform.config_digest/></div><div><span>"OS version"</span><strong>{display_or(&platform.os_version, "unspecified")}</strong></div><div><span>"OS features"</span><strong>{display_or(&os_features, "none")}</strong></div><div><span>"Compressed"</span><strong>{format_bytes(platform.compressed_byte_size)}</strong></div><div><span>"Unpacked"</span><strong>{format_bytes(platform.unpacked_byte_size)}</strong></div><div><span>"Layers"</span><strong>{platform.layer_count}</strong></div></div>{(!platform.config_json.is_empty()).then(|| view! { <details><summary>"Parsed image config"</summary><pre class="json-view">{platform.config_json}</pre></details> })}</article> }
}

#[component]
fn LayerRow(layer: aos_proto_types::ContainerLayer) -> impl IntoView {
    view! { <div class="compact-list-row"><div><strong>{format!("Layer {}", layer.ordinal)}</strong><span>{format!("{} compressed · {} unpacked · shared by {} repositories", format_bytes(layer.compressed_byte_size), format_bytes(layer.unpacked_byte_size), layer.shared_repository_count)}</span><small>{display_or(&layer.closure_group, "no closure group")}</small><small>{format!("root {}", layer.root_digest)}</small></div><HashValue value=layer.digest/></div> }
}

#[component]
fn ReferrerRow(referrer: aos_proto_types::ContainerReferrer) -> impl IntoView {
    view! { <div class="compact-list-row"><div><strong>{display_or(&referrer.artifact_type, "OCI artifact")}</strong><span>{format!("{} · {}", referrer.media_type, format_bytes(referrer.byte_size))}</span></div><HashValue value=referrer.digest/><StatusBadge state=referrer.verification.clone() positive=referrer.verification == "verified"/></div> }
}

#[component]
fn ProvenanceDetail(provenance: aos_proto_types::ContainerProvenance) -> impl IntoView {
    view! {
        <section class="subworkflow"><div class="section-heading"><div><p class="section-kicker">"Signed AOS release graph"</p><h3>"Provenance"</h3></div><StatusBadge state=provenance.verification.clone() positive=provenance.verification == "verified"/></div><div class="resource-identity"><div><span>"Package"</span><strong>{provenance.package}</strong></div><div><span>"Release"</span><strong>{provenance.release}</strong></div><div><span>"Channel"</span><strong>{display_or(&provenance.channel, "release only")}</strong></div><div><span>"Signed root"</span><HashValue value=provenance.signed_release_root/></div><div><span>"Catalog"</span><HashValue value=provenance.catalog_digest/></div></div><h4>"Nix closure members"</h4><div class="compact-list">{provenance.closure_members.into_iter().map(|member| view! { <div class="compact-list-row"><div><strong>{member.store_path}</strong><span>{format!("{} NAR bytes{}", member.nar_size, if member.direct { " · direct" } else { "" })}</span></div><HashValue value=member.nar_hash/></div> }).collect_view()}</div><h4>"Evidence"</h4><div class="compact-list">{provenance.evidence.into_iter().map(|evidence| view! { <div class="compact-list-row"><div><strong>{evidence.kind}</strong><span>{evidence.media_type}</span></div><HashValue value=evidence.digest/><StatusBadge state=evidence.verification.clone() positive=evidence.verification == "verified"/></div> }).collect_view()}</div></section>
    }
}
