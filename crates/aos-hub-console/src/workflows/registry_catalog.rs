//! Registry package and rollout-channel catalog workflows.
//!
//! Package metadata describes signed version/platform artifacts. Channels map
//! rollout partitions to release identities and remain distinct from mutable
//! publication pointers and cache-retention selectors.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HashValue, InlineError, StatusBadge};
use crate::transport::ApiClient;

/// Renders the package or channel catalog selected by the canonical page.
#[component]
pub(super) fn RegistryCatalog(
    client: ApiClient,
    registry_id: String,
    page: &'static str,
) -> impl IntoView {
    match page {
        "packages" => view! { <Packages client=client registry_id=registry_id/> }.into_any(),
        "docs" => {
            view! { <DocumentationBrowser client=client registry_id=registry_id/> }.into_any()
        }
        "channels" => view! { <Channels client=client registry_id=registry_id/> }.into_any(),
        _ => view! { <InlineError detail="Unknown registry catalog page".to_string()/> }.into_any(),
    }
}

#[component]
fn Packages(client: ApiClient, registry_id: String) -> impl IntoView {
    let list_client = client.clone();
    let list_registry = registry_id.clone();
    let packages = LocalResource::new(move || {
        let client = list_client.clone();
        let registry = list_registry.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListPackagesResponse, _, _, _>(
                    aos_proto_types::PACKAGE_SERVICE_LIST_PACKAGES_PATH,
                    move |page_token| aos_proto_types::ListPackagesRequest {
                        slug: registry.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.packages, response.next_page_token),
                )
                .await
        }
    });

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"Signed package index"</p><h2>"Packages"</h2></div></div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading packages…"</p> }>
                    {move || Suspend::new(async move {
                        match packages.await.as_ref() {
                            Ok(packages) if packages.is_empty() => view! { <p class="muted">"No indexed packages."</p> }.into_any(),
                            Ok(packages) => view! { <div class="binding-list">{packages.iter().cloned().map(|package| view! { <PackageSummaryCard package=package/> }).collect_view()}</div> }.into_any(),
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })}
                </Suspense>
            </section>
            <PackageInspector client=client.clone() registry_id=registry_id.clone()/>
            <DocumentationBrowser client=client registry_id=registry_id/>
        </div>
    }
}

#[component]
fn PackageSummaryCard(package: aos_proto_types::PackageSummary) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row"><div><strong>{package.name}</strong><span>{package.description}</span></div><StatusBadge state=package.latest_version positive=true/></div>
            <div class="compact-list-row"><span>"License"</span><strong>{package.license}</strong></div>
        </article>
    }
}

#[component]
fn PackageInspector(client: ApiClient, registry_id: String) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let package = RwSignal::new(None::<aos_proto_types::Package>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let name = name.get_untracked().trim().to_string();
        if name.is_empty() {
            error.set(Some("Package name is required".to_string()));
            return;
        }
        let client = client.clone();
        let registry = registry_id.clone();
        error.set(None);
        package.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::GetPackageResponse>(
                    aos_proto_types::PACKAGE_SERVICE_GET_PACKAGE_PATH,
                    &aos_proto_types::GetPackageRequest {
                        slug: registry,
                        name,
                    },
                )
                .await
            {
                Ok(response) => package.set(response.package),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div><p class="section-kicker">"All versions and platforms"</p><h2>"Inspect package"</h2></div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label><span>"Package name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Load package"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || package.get().map(|package| view! { <PackageDetail package=package/> })}
        </section>
    }
}

#[component]
fn PackageDetail(package: aos_proto_types::Package) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{package.name}</strong><span>{package.description}</span></div>
                <StatusBadge state=if package.sysroot { "sysroot" } else { "package" }.to_string() positive=package.sysroot/>
            </div>
            <div class="resource-identity">
                <div><span>"Homepage"</span><span>{package.homepage}</span></div>
                <div><span>"License"</span><strong>{package.license}</strong></div>
                <div><span>"Maintainer"</span><strong>{package.maintainer}</strong></div>
            </div>
            {package.versions.into_iter().map(|version| view! {
                <section class="subworkflow">
                    <h4>{version.version}</h4>
                    <span>{format!("previous: {}", display_or(&version.previous, "none"))}</span>
                    <div class="compact-list">
                        {version.platforms.into_iter().map(|platform| view! {
                            <div class="compact-list-row">
                                <strong>{platform.platform}</strong><HashValue value=platform.nar_hash/>
                                <span>{format!("{} NAR bytes · {} closure bytes", platform.nar_size, platform.closure_size)}</span>
                            </div>
                        }).collect_view()}
                    </div>
                </section>
            }).collect_view()}
        </article>
    }
}

#[component]
fn DocumentationBrowser(client: ApiClient, registry_id: String) -> impl IntoView {
    let query = RwSignal::new(String::new());
    let kind = RwSignal::new(String::new());
    let results = RwSignal::new(Vec::<aos_proto_types::PackageDocumentationSearchResult>::new());
    let selected = RwSignal::new(None::<aos_doc_model::PackageDocumentation>);
    let selected_identity = RwSignal::new(None::<aos_proto_types::PackageDocumentationIdentity>);
    let selected_options = RwSignal::new(Vec::<aos_proto_types::PackageOptionView>::new());
    let selected_option = RwSignal::new(None::<aos_proto_types::PackageOptionView>);
    let compare_to = RwSignal::new(String::new());
    let comparison = RwSignal::new(None::<aos_doc_model::DocumentationComparison>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let schema_client = client.clone();
    let schema = LocalResource::new(move || {
        let client = schema_client.clone();
        async move {
            client
                .call::<_, aos_proto_types::GetPackageDocumentationSchemaResponse>(
                    aos_proto_types::DOCUMENTATION_SERVICE_GET_PACKAGE_DOCUMENTATION_SCHEMA_PATH,
                    &aos_proto_types::GetPackageDocumentationSchemaRequest {},
                )
                .await
        }
    });

    let search_client = client.clone();
    let search_registry = registry_id.clone();
    let on_search = move |event: SubmitEvent| {
        event.prevent_default();
        let client = search_client.clone();
        let registry = search_registry.clone();
        let search_query = query.get_untracked();
        let search_kind = kind.get_untracked();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::SearchPackageDocumentationResponse>(
                    aos_proto_types::DOCUMENTATION_SERVICE_SEARCH_PACKAGE_DOCUMENTATION_PATH,
                    &aos_proto_types::SearchPackageDocumentationRequest {
                        registry,
                        query: search_query,
                        kind: search_kind,
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await
            {
                Ok(response) => results.set(response.results),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    let compare_client = client.clone();
    let compare_registry = registry_id.clone();
    let on_compare = move |event: SubmitEvent| {
        event.prevent_default();
        let Some(identity) = selected_identity.get_untracked() else {
            error.set(Some(
                "Select package documentation before comparing versions".to_string(),
            ));
            return;
        };
        let destination = compare_to.get_untracked().trim().to_string();
        if destination.is_empty() {
            error.set(Some("Destination version is required".to_string()));
            return;
        }
        let client = compare_client.clone();
        let registry = compare_registry.clone();
        error.set(None);
        comparison.set(None);
        busy.set(true);
        spawn_local(async move {
            match compare_documentation(&client, registry, &identity, destination).await {
                Ok(value) => comparison.set(Some(value)),
                Err(detail) => error.set(Some(detail)),
            }
            busy.set(false);
        });
    };
    let result_client = client.clone();
    let result_registry = registry_id.clone();
    let option_client_root = client;
    let option_registry_root = registry_id;

    view! {
        <section class="panel resource-panel documentation-browser">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Canonical package reference"</p>
                    <h2>"Documentation browser"</h2>
                    <p class="muted">"Search option, service, credential, capability, and package docs extracted from the exact signed Nix objects you can install."</p>
                </div>
                <Suspense fallback=move || view! { <span class="muted">"Loading schema…"</span> }>
                    {move || Suspend::new(async move {
                        match schema.await.as_ref() {
                            Ok(schema) => view! { <StatusBadge state=schema.schema.clone() positive=true/> }.into_any(),
                            Err(failure) => view! { <span class="muted">{format!("Schema unavailable: {failure}")}</span> }.into_any(),
                        }
                    })}
                </Suspense>
            </div>
            <form class="editor-form documentation-search" on:submit=on_search>
                <label class="full-field"><span>"Search docs"</span><input placeholder="TLS, listen port, credential, restart…" prop:value=move || query.get() on:input=move |event| query.set(event_target_value(&event))/></label>
                <label><span>"Kind"</span><select prop:value=move || kind.get() on:change=move |event| kind.set(event_target_value(&event))>
                    <option value="">"Everything"</option>
                    <option value="package">"Packages"</option>
                    <option value="option">"Options"</option>
                    <option value="service">"Services"</option>
                    <option value="credential">"Credentials"</option>
                    <option value="capability">"Capabilities"</option>
                </select></label>
                <button class="button" type="submit" disabled=move || busy.get()>"Search documentation"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || {
                let entries = results.get();
                (!entries.is_empty()).then(|| view! {
                    <div class="documentation-results" aria-label="Documentation search results">
                        {entries.into_iter().map(|entry| {
                            let load_client = result_client.clone();
                            let load_registry = result_registry.clone();
                            let package = entry.package.clone();
                            let version = entry.version.clone();
                            let platform = entry.platform.clone();
                            view! {
                                <button class="documentation-result" type="button" on:click=move |_| {
                                    let client = load_client.clone();
                                    let registry = load_registry.clone();
                                    let package = package.clone();
                                    let version = version.clone();
                                    let platform = platform.clone();
                                    error.set(None);
                                    busy.set(true);
                                    spawn_local(async move {
                                        match load_documentation(&client, registry, package, version, platform).await {
                                            Ok((document, identity, options)) => {
                                                selected.set(Some(document));
                                                selected_identity.set(identity);
                                                selected_options.set(options);
                                                selected_option.set(None);
                                                comparison.set(None);
                                            }
                                            Err(detail) => error.set(Some(detail)),
                                        }
                                        busy.set(false);
                                    });
                                }>
                                    <span class="documentation-result-kind">{entry.kind}</span>
                                    <strong>{entry.title}</strong>
                                    <span>{entry.summary}</span>
                                    <code>{format!("{} {} · {}", entry.package, entry.version, entry.platform)}</code>
                                </button>
                            }
                        }).collect_view()}
                    </div>
                })
            }}
            {move || selected.get().map(|document| {
                let html = document.render_html_fragment();
                let identity = selected_identity.get();
                view! {
                    <article class="documentation-detail">
                        {identity.map(|identity| view! {
                            <div class="resource-identity documentation-identity">
                                <div><span>"Store object"</span><code>{identity.store_path}</code></div>
                                <div><span>"Document SHA-256"</span><HashValue value=identity.document_sha256/></div>
                                <div><span>"Semantic schema"</span><HashValue value=identity.semantic_schema_sha256/></div>
                            </div>
                        })}
                        <div class="documentation-content" inner_html=html></div>
                        <section class="subworkflow">
                            <h3>"Option explorer"</h3>
                            <div class="documentation-results">
                                {selected_options.get().into_iter().map(|option| {
                                    let option_client = option_client_root.clone();
                                    let option_registry = option_registry_root.clone();
                                    let identity = option.identity.clone();
                                    let path = option.path.clone();
                                    view! {
                                        <button class="documentation-result" type="button" on:click=move |_| {
                                            let Some(identity) = identity.clone() else { return; };
                                            let client = option_client.clone();
                                            let registry = option_registry.clone();
                                            let path = path.clone();
                                            spawn_local(async move {
                                                match load_package_option(&client, registry, identity, path).await {
                                                    Ok(option) => selected_option.set(Some(option)),
                                                    Err(detail) => error.set(Some(detail)),
                                                }
                                            });
                                        }>
                                            <strong>{option.display_path}</strong>
                                            <span>{option.r#type}</span>
                                            <code>{format!("owner {} · contributable {}", option.owner_package, option.contributable)}</code>
                                        </button>
                                    }
                                }).collect_view()}
                            </div>
                            {move || selected_option.get().map(|option| view! {
                                <article class="revision-card">
                                    <h4>{option.display_path}</h4>
                                    <div class="resource-identity">
                                        <div><span>"Type"</span><strong>{option.r#type}</strong></div>
                                        <div><span>"Owner"</span><strong>{format!("{} / {}", option.owner_package, option.owner_root)}</strong></div>
                                    </div>
                                </article>
                            })}
                        </section>
                    </article>
                }
            })}
            <section class="subworkflow">
                <h3>"Compare semantic versions"</h3>
                <form class="editor-form" on:submit=on_compare>
                    <label><span>"Destination version"</span><input placeholder="1.31.0" prop:value=move || compare_to.get() on:input=move |event| compare_to.set(event_target_value(&event))/></label>
                    <button class="secondary-button" type="submit" disabled=move || busy.get() || selected_identity.get().is_none()>"Compare"</button>
                </form>
                {move || comparison.get().map(|comparison| view! {
                    <article class="revision-card">
                        <div class="compact-list-row"><strong>{format!("{} → {}", comparison.from_version, comparison.to_version)}</strong><StatusBadge state=if comparison.semantic_changed { "semantic change" } else { "prose-only" }.to_string() positive=!comparison.semantic_changed/></div>
                        <p>{format!("{} option changes · runtime changed: {}", comparison.option_changes.len(), comparison.runtime_changed)}</p>
                        <div class="compact-list">{comparison.option_changes.into_iter().map(|change| view! { <div class="compact-list-row"><code>{change.path}</code><span>{format!("{:?}", change.kind)}</span></div> }).collect_view()}</div>
                    </article>
                })}
            </section>
        </section>
    }
}

async fn load_documentation(
    client: &ApiClient,
    registry: String,
    package: String,
    version: String,
    platform: String,
) -> Result<
    (
        aos_doc_model::PackageDocumentation,
        Option<aos_proto_types::PackageDocumentationIdentity>,
        Vec<aos_proto_types::PackageOptionView>,
    ),
    String,
> {
    let response = client
        .call::<_, aos_proto_types::GetPackageDocumentationResponse>(
            aos_proto_types::DOCUMENTATION_SERVICE_GET_PACKAGE_DOCUMENTATION_PATH,
            &aos_proto_types::GetPackageDocumentationRequest {
                registry: registry.clone(),
                package,
                version,
                platform,
            },
        )
        .await
        .map_err(|failure| failure.to_string())?;
    let document =
        aos_doc_model::PackageDocumentation::from_canonical_json(&response.canonical_json)
            .map_err(|failure| format!("Hub returned invalid package documentation: {failure}"))?;
    let identity = response.identity;
    let identity_ref = identity
        .as_ref()
        .ok_or_else(|| "Hub documentation omitted identity".to_string())?;
    let artifact = client
        .call::<_, aos_proto_types::GetPackageDocumentationResponse>(
            aos_proto_types::DOCUMENTATION_SERVICE_GET_DOCUMENTATION_ARTIFACT_PATH,
            &aos_proto_types::GetDocumentationArtifactRequest {
                registry: registry.clone(),
                document_sha256: identity_ref.document_sha256.clone(),
            },
        )
        .await
        .map_err(|failure| failure.to_string())?;
    if artifact.canonical_json != response.canonical_json || artifact.etag != response.etag {
        return Err(
            "immutable documentation artifact disagrees with package selection".to_string(),
        );
    }
    let options = client
        .call::<_, aos_proto_types::ListPackageOptionsResponse>(
            aos_proto_types::DOCUMENTATION_SERVICE_LIST_PACKAGE_OPTIONS_PATH,
            &aos_proto_types::ListPackageOptionsRequest {
                registry,
                package: identity_ref.package.clone(),
                version: identity_ref.version.clone(),
                platform: identity_ref.platform.clone(),
                prefix: String::new(),
                owner: String::new(),
                r#type: String::new(),
                contributable: None,
                page_size: 100,
                page_token: String::new(),
            },
        )
        .await
        .map_err(|failure| failure.to_string())?;
    Ok((document, identity, options.options))
}

async fn load_package_option(
    client: &ApiClient,
    registry: String,
    identity: aos_proto_types::PackageDocumentationIdentity,
    path: Vec<aos_proto_types::DocumentationPathSegment>,
) -> Result<aos_proto_types::PackageOptionView, String> {
    client
        .call::<_, aos_proto_types::GetPackageOptionResponse>(
            aos_proto_types::DOCUMENTATION_SERVICE_GET_PACKAGE_OPTION_PATH,
            &aos_proto_types::GetPackageOptionRequest {
                registry,
                package: identity.package,
                version: identity.version,
                platform: identity.platform,
                path,
            },
        )
        .await
        .map_err(|failure| failure.to_string())?
        .option
        .ok_or_else(|| "Hub package option response omitted its option".to_string())
}

async fn compare_documentation(
    client: &ApiClient,
    registry: String,
    identity: &aos_proto_types::PackageDocumentationIdentity,
    to_version: String,
) -> Result<aos_doc_model::DocumentationComparison, String> {
    let response = client
        .call::<_, aos_proto_types::ComparePackageDocumentationResponse>(
            aos_proto_types::DOCUMENTATION_SERVICE_COMPARE_PACKAGE_DOCUMENTATION_PATH,
            &aos_proto_types::ComparePackageDocumentationRequest {
                registry,
                package: identity.package.clone(),
                from_version: identity.version.clone(),
                to_version,
                platform: identity.platform.clone(),
            },
        )
        .await
        .map_err(|failure| failure.to_string())?;
    serde_json::from_slice(&response.canonical_comparison_json)
        .map_err(|failure| format!("Hub returned invalid documentation comparison: {failure}"))
}

#[component]
fn Channels(client: ApiClient, registry_id: String) -> impl IntoView {
    let list_client = client.clone();
    let list_registry = registry_id.clone();
    let channels = LocalResource::new(move || {
        let client = list_client.clone();
        let registry = list_registry.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListChannelsResponse, _, _, _>(
                    aos_proto_types::CHANNEL_SERVICE_LIST_CHANNELS_PATH,
                    move |page_token| aos_proto_types::ListChannelsRequest {
                        slug: registry.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.channels, response.next_page_token),
                )
                .await
        }
    });
    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"256-partition rollout map"</p><h2>"Channels"</h2></div></div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading channels…"</p> }>
                    {move || Suspend::new(async move {
                        match channels.await.as_ref() {
                            Ok(channels) if channels.is_empty() => view! { <p class="muted">"No indexed channels."</p> }.into_any(),
                            Ok(channels) => view! { <div class="binding-list">{channels.iter().cloned().map(|channel| view! { <ChannelCard channel=channel/> }).collect_view()}</div> }.into_any(),
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })}
                </Suspense>
            </section>
            <ChannelInspector client=client registry_id=registry_id/>
        </div>
    }
}

#[component]
fn ChannelInspector(client: ApiClient, registry_id: String) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let channel = RwSignal::new(None::<aos_proto_types::Channel>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let name = name.get_untracked().trim().to_string();
        if name.is_empty() {
            error.set(Some("Channel name is required".to_string()));
            return;
        }
        let client = client.clone();
        let registry = registry_id.clone();
        error.set(None);
        channel.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::GetChannelResponse>(
                    aos_proto_types::CHANNEL_SERVICE_GET_CHANNEL_PATH,
                    &aos_proto_types::GetChannelRequest {
                        slug: registry,
                        name,
                    },
                )
                .await
            {
                Ok(response) => channel.set(response.channel),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Exact assignment map"</p><h2>"Inspect channel"</h2></div></div>
            <form class="editor-form" on:submit=on_submit>
                <label><span>"Channel name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>"Load channel"</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || channel.get().map(|channel| view! { <ChannelCard channel=channel/> })}
        </section>
    }
}

#[component]
fn ChannelCard(channel: aos_proto_types::Channel) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row"><div><strong>{channel.name}</strong><span>{format!("{} assigned partitions", channel.partitions.len())}</span></div><StatusBadge state=channel.frontier positive=true/></div>
            <details><summary>"Partition assignments"</summary><div class="compact-list">
                {channel.partitions.into_iter().map(|partition| view! {
                    <div class="compact-list-row"><strong>{partition.bucket}</strong><code>{partition.release}</code></div>
                }).collect_view()}
            </div></details>
        </article>
    }
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}
