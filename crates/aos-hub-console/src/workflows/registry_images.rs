//! Signed AOS system-image discovery and direct downloads.
//!
//! Images are disk encodings attached to verified registry releases. Users
//! select release/channel, architecture, format, or deployment target without
//! interacting with Nix store paths or NAR transport details.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, StatusBadge};
use crate::transport::ApiClient;

#[derive(Clone, Copy)]
struct ImageFilters {
    release: RwSignal<String>,
    channel: RwSignal<String>,
    architecture: RwSignal<String>,
    format: RwSignal<String>,
    target: RwSignal<String>,
    package: RwSignal<String>,
}

impl ImageFilters {
    fn new() -> Self {
        Self {
            release: RwSignal::new(String::new()),
            channel: RwSignal::new(String::new()),
            architecture: RwSignal::new(String::new()),
            format: RwSignal::new(String::new()),
            target: RwSignal::new(String::new()),
            package: RwSignal::new(String::new()),
        }
    }

    fn request(self, slug: String, page_token: String) -> aos_proto_types::ListImagesRequest {
        aos_proto_types::ListImagesRequest {
            slug,
            release: self.release.get_untracked().trim().to_string(),
            channel: self.channel.get_untracked().trim().to_string(),
            architecture: self.architecture.get_untracked().trim().to_string(),
            format: self.format.get_untracked().trim().to_string(),
            target: self.target.get_untracked().trim().to_string(),
            page_size: 100,
            page_token,
            package: self.package.get_untracked().trim().to_string(),
        }
    }
}

/// Renders discoverable signed system images and immutable download actions.
#[component]
pub(super) fn RegistryImages(client: ApiClient, registry_id: String) -> impl IntoView {
    let filters = ImageFilters::new();
    let images = RwSignal::new(None::<Vec<aos_proto_types::SystemImage>>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let client = client.clone();
        let registry_id = registry_id.clone();
        error.set(None);
        images.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .collect_pages::<_, aos_proto_types::ListImagesResponse, _, _, _>(
                    aos_proto_types::IMAGE_SERVICE_LIST_IMAGES_PATH,
                    move |page_token| filters.request(registry_id.clone(), page_token),
                    |response| (response.images, response.next_page_token),
                )
                .await
            {
                Ok(response) => images.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Verified disk artifacts"</p>
                    <h2>"AOS system images"</h2>
                    <p>"Choose a deployment target and download exact disk-image bytes from the signed release catalog."</p>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label><span>"Release"</span><input placeholder="1.2.3" prop:value=move || filters.release.get() on:input=move |event| filters.release.set(event_target_value(&event))/></label>
                <label><span>"Channel"</span><input placeholder="stable" prop:value=move || filters.channel.get() on:input=move |event| filters.channel.set(event_target_value(&event))/></label>
                <label><span>"Architecture"</span><input placeholder="x86_64" prop:value=move || filters.architecture.get() on:input=move |event| filters.architecture.set(event_target_value(&event))/></label>
                <label><span>"Format"</span><select prop:value=move || filters.format.get() on:change=move |event| filters.format.set(event_target_value(&event))><option value="">"Any format"</option><option value="raw">"Raw"</option><option value="qcow2">"QCOW2"</option><option value="vmdk">"VMDK"</option><option value="vhd">"VHD"</option></select></label>
                <label><span>"Target"</span><select prop:value=move || filters.target.get() on:change=move |event| filters.target.set(event_target_value(&event))><option value="">"Any target"</option><option value="bare-metal">"Bare metal"</option><option value="qemu">"QEMU/KVM"</option><option value="openstack">"OpenStack"</option><option value="vmware">"VMware"</option><option value="hyper-v">"Hyper-V"</option></select></label>
                <label><span>"Package"</span><input placeholder="aos-sysroot" prop:value=move || filters.package.get() on:input=move |event| filters.package.set(event_target_value(&event))/></label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>{move || if busy.get() { "Resolving…" } else { "Find images" }}</button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || images.get().map(|images| {
                if images.is_empty() {
                    view! { <p class="muted">"No signed images match these filters."</p> }.into_any()
                } else {
                    view! { <div class="binding-list">{images.into_iter().map(|image| view! { <ImageCard image=image/> }).collect_view()}</div> }.into_any()
                }
            })}
        </section>
    }
}

#[component]
fn ImageCard(image: aos_proto_types::SystemImage) -> impl IntoView {
    let info = image.image_info.clone().unwrap_or_default();
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{image.filename.clone()}</strong><span>{format!("{} · {} · {}", image.release, image.architecture, image.format)}</span></div>
                <StatusBadge state=image.release_verification.clone() positive=image.release_verification == "verified"/>
            </div>
            <div class="resource-identity">
                <div><span>"Channel"</span><strong>{display_or(&image.channel, "release only")}</strong></div>
                <div><span>"Platform"</span><strong>{image.platform}</strong></div>
                <div><span>"Size"</span><strong>{format_bytes(image.byte_size)}</strong></div>
                <div><span>"Media type"</span><code>{image.media_type}</code></div>
                <div><span>"Compression"</span><strong>{display_or(&image.compression, "none")}</strong></div>
                <div><span>"Boot verification"</span><strong>{image.boot_verification}</strong></div>
            </div>
            <div class="compact-list-row"><span>"SHA-256"</span><code>{image.sha256}</code></div>
            <div class="compact-list-row"><span>"Compatible targets"</span><span>{image.compatible_targets.join(", ")}</span></div>
            <div class="form-actions">
                <a class="button" href=image.download_url download=image.filename>"Download image"</a>
                {(!info.download_url.is_empty()).then(|| view! {
                    <a class="secondary-button" href=info.download_url download=info.filename>"Download image-info.json"</a>
                })}
            </div>
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

fn format_bytes(value: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if value >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", value as f64 / GIB)
    } else if value >= 1024 * 1024 {
        format!("{:.1} MiB", value as f64 / MIB)
    } else {
        format!("{value} bytes")
    }
}
