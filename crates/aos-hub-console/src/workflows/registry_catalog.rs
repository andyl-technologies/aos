//! Registry package and rollout-channel catalog workflows.
//!
//! Package metadata describes signed version/platform artifacts. Channels map
//! rollout partitions to release identities and remain distinct from mutable
//! publication pointers and cache-retention selectors.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, StatusBadge};
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
            <PackageInspector client=client registry_id=registry_id/>
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
                                <strong>{platform.platform}</strong><code>{platform.nar_hash}</code>
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
