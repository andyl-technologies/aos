//! Deployment-wide branding, identity, and resource-default settings.
//!
//! The three editors share one exact-version settings bundle. Each mutation
//! submits only its owned keys while preserving the server's immutable
//! plan/review/apply boundary.

use std::collections::HashMap;

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{HelpTooltip, InlineError, ReviewedPlanCard};
use crate::mutation::{idempotency_key, watch_draft, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::organization_identity::OrganizationIdentityWorkflow;

/// Renders instance-setting workflows and delegates unrelated pages onward.
#[component]
pub(super) fn InstanceSettingsWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "overview" | "identity" | "resource-defaults" | "branding") => {
            view! { <InstanceSettingsPage client=client page=route.page.key/> }.into_any()
        }
        _ => view! { <OrganizationIdentityWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn InstanceSettingsPage(client: ApiClient, page: &'static str) -> impl IntoView {
    let read_client = client.clone();
    let settings = LocalResource::new(move || {
        let client = read_client.clone();
        async move {
            client
                .call::<_, aos_proto_types::GetInstanceSettingsResponse>(
                    aos_proto_types::INSTANCE_SERVICE_GET_INSTANCE_SETTINGS_PATH,
                    &aos_proto_types::GetInstanceSettingsRequest {},
                )
                .await
        }
    });

    view! {
        <Suspense fallback=move || view! { <section class="panel"><p class="loading-row">"Loading instance settings…"</p></section> }>
            {move || {
                let client = client.clone();
                Suspend::new(async move {
                    match settings.await.as_ref() {
                        Ok(response) => {
                            let values = response.settings.clone().unwrap_or_default();
                            let version = response.resource_version.clone();
                            match page {
                                "overview" => view! { <InstanceOverview settings=values version=version/> }.into_any(),
                                "identity" => view! { <IdentitySettings client=client settings=values version=version/> }.into_any(),
                                "resource-defaults" => view! { <ResourceDefaults client=client settings=values version=version/> }.into_any(),
                                "branding" => view! { <BrandingSettings client=client settings=values version=version/> }.into_any(),
                                _ => ().into_any(),
                            }
                        }
                        Err(failure) => view! { <section class="panel"><InlineError detail=failure.to_string()/></section> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn InstanceOverview(settings: aos_proto_types::InstanceSettings, version: String) -> impl IntoView {
    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div><p class="section-kicker">"Deployment control plane"</p><h2>{display_or(&settings.site_title, "AOS Hub")}</h2><p>{display_or(&settings.tagline, "Instance settings and topology")}</p></div>
                </div>
                <div class="resource-identity">
                    <div><span>"Signup"</span><strong>{signup_policy_label(&settings.signup_policy)}</strong></div>
                    <div><span>"Password login"</span><strong>{enabled_disabled(settings.password_login)}</strong></div>
                    <div><span>"Public cache discovery"</span><strong>{enabled_disabled(settings.caches_public)}</strong></div>
                    <div><span>"Default crawl policy"</span><strong>{crawl_policy_label(&settings.default_crawl_policy)}</strong></div>
                </div>
                <details><summary>"Instance metadata"</summary><div class="resource-identity"><div><span>"Settings version"</span><code>{version}</code></div></div></details>
            </section>
            <section class="resource-grid">
                <a class="resource-card" href="/-/instance/identity-and-signup"><div><span class="resource-kind">"Access"</span><h3>"Identity & signup"</h3><p>"Signup eligibility, login methods, and session lifetime."</p></div></a>
                <a class="resource-card" href="/-/instance/resource-defaults"><div><span class="resource-kind">"Policy"</span><h3>"Resource defaults"</h3><p>"Upload limits, cache discovery, and registry crawl policy."</p></div></a>
                <a class="resource-card" href="/-/instance/branding"><div><span class="resource-kind">"Appearance"</span><h3>"Branding"</h3><p>"Site identity, announcements, legal links, and support."</p></div></a>
            </section>
            <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"Shared infrastructure"</p><h2>"Delivery and storage"</h2><p>"Resources owned by the instance and granted to organizations, registries, and caches."</p></div></div>
                <div class="resource-grid">
                    <a class="resource-card" href="/-/instance/bindings"><div><span class="resource-kind">"Storage"</span><h3>"Bindings"</h3><p>"Credentials and object-store connections."</p></div></a>
                    <a class="resource-card" href="/-/instance/domains"><div><span class="resource-kind">"Delivery"</span><h3>"Domains"</h3><p>"Hostname ownership and certificate intent."</p></div></a>
                    <a class="resource-card" href="/-/instance/network-policies"><div><span class="resource-kind">"Network"</span><h3>"Network policies"</h3><p>"Trusted ingress, source, and probe requirements."</p></div></a>
                    <a class="resource-card" href="/-/instance/endpoints"><div><span class="resource-kind">"Delivery"</span><h3>"Endpoints"</h3><p>"Ingress identity, listener state, and verification."</p></div></a>
                    <a class="resource-card" href="/-/instance/gateways"><div><span class="resource-kind">"Delivery"</span><h3>"Gateways"</h3><p>"Exact storage-to-endpoint generations."</p></div></a>
                    <a class="resource-card" href="/-/instance/topology-defaults"><div><span class="resource-kind">"Defaults"</span><h3>"Topology defaults"</h3><p>"Starting choices for future storage and delivery plans."</p></div></a>
                </div>
            </section>
        </div>
    }
}

#[component]
fn IdentitySettings(
    client: ApiClient,
    settings: aos_proto_types::InstanceSettings,
    version: String,
) -> impl IntoView {
    let signup_policy = RwSignal::new(settings.signup_policy);
    let signup_domains = RwSignal::new(settings.signup_domains.join("\n"));
    let password_login = RwSignal::new(settings.password_login);
    let session_lifetime = RwSignal::new(settings.session_lifetime_secs.to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = (
                signup_policy.get(),
                signup_domains.get(),
                password_login.get(),
                session_lifetime.get(),
            );
        },
        pending,
        error,
    );
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
        let domains = normalized_lines(&signup_domains.get_untracked()).join(",");
        let lifetime = match non_negative(&session_lifetime.get_untracked(), "Session lifetime") {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let values = HashMap::from([
            ("signup_policy".to_string(), signup_policy.get_untracked()),
            ("signup_domains".to_string(), domains),
            (
                "password_login".to_string(),
                on_off(password_login.get_untracked()).to_string(),
            ),
            ("session_lifetime_secs".to_string(), lifetime),
        ]);
        plan_settings(
            plan_client.clone(),
            "identity",
            values,
            version.clone(),
            pending,
            error,
            busy,
            draft_epoch,
        );
    };
    let on_apply = apply_settings(client, pending, error, busy);

    view! {
        <section class="panel editor-panel">
            <div class="section-heading"><div><p class="section-kicker">"Access & trust"</p><h2>"Identity & signup"</h2><p>"Choose who may create an account and which local login options the Hub offers."</p></div></div>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Signup policy"</span><select prop:value=move || signup_policy.get() on:change=move |event| signup_policy.set(event_target_value(&event))><option value="invite_only">"Invite only"</option><option value="open">"Open"</option></select></label>
                <label><span>"Session lifetime in seconds"<HelpTooltip term="Session lifetime" summary="Enter 0 to use the Hub default. Existing sessions keep their original expiry."/></span><input required type="number" min="0" prop:value=move || session_lifetime.get() on:input=move |event| session_lifetime.set(event_target_value(&event))/></label>
                <label class="checkbox-field"><input type="checkbox" prop:checked=move || password_login.get() on:change=move |event| password_login.set(event_target_checked(&event))/><span>"Offer local password login"</span></label>
                <label class="full-field"><span>"Allowed signup domains"<HelpTooltip term="Allowed signup domains" summary="Enter one email domain per line. An empty list allows every domain when signup is open."/></span><textarea placeholder="example.com" prop:value=move || signup_domains.get() on:input=move |event| signup_domains.set(event_target_value(&event))></textarea></label>
                <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review identity settings"</button></div>
            </form>
            <SettingsReview pending=pending error=error busy=busy on_apply=on_apply/>
        </section>
    }
}

#[component]
fn ResourceDefaults(
    client: ApiClient,
    settings: aos_proto_types::InstanceSettings,
    version: String,
) -> impl IntoView {
    let crawl_policy = RwSignal::new(settings.default_crawl_policy);
    let max_upload = RwSignal::new(settings.max_upload_bytes.to_string());
    let caches_public = RwSignal::new(settings.caches_public);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = (crawl_policy.get(), max_upload.get(), caches_public.get());
        },
        pending,
        error,
    );
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
        let max_upload = match non_negative(&max_upload.get_untracked(), "Maximum upload size") {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let values = HashMap::from([
            (
                "default_crawl_policy".to_string(),
                crawl_policy.get_untracked(),
            ),
            ("max_upload_bytes".to_string(), max_upload),
            (
                "caches_public".to_string(),
                on_off(caches_public.get_untracked()).to_string(),
            ),
        ]);
        plan_settings(
            plan_client.clone(),
            "resource-defaults",
            values,
            version.clone(),
            pending,
            error,
            busy,
            draft_epoch,
        );
    };
    let on_apply = apply_settings(client, pending, error, busy);

    view! {
        <section class="panel editor-panel">
            <div class="section-heading"><div><p class="section-kicker">"Inherited policy"</p><h2>"Resource defaults"</h2><p>"New registries and caches start with these policies. A resource-level setting may override them later."</p></div></div>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Default registry crawl policy"</span><select prop:value=move || crawl_policy.get() on:change=move |event| crawl_policy.set(event_target_value(&event))><option value="allow_all">"Allow all"</option><option value="allow_no_ai">"Allow, excluding AI crawlers"</option><option value="deny_all">"Deny all"</option></select></label>
                <label><span>"Maximum upload size in bytes"<HelpTooltip term="Maximum upload size" summary="Enter 0 to use the Hub default. The reviewed plan shows the stored byte value."/></span><input required type="number" min="0" prop:value=move || max_upload.get() on:input=move |event| max_upload.set(event_target_value(&event))/></label>
                <label class="checkbox-field"><input type="checkbox" prop:checked=move || caches_public.get() on:change=move |event| caches_public.set(event_target_checked(&event))/><span>"Expose cache discovery publicly"</span></label>
                <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review resource defaults"</button></div>
            </form>
            <SettingsReview pending=pending error=error busy=busy on_apply=on_apply/>
        </section>
    }
}

#[component]
fn BrandingSettings(
    client: ApiClient,
    settings: aos_proto_types::InstanceSettings,
    version: String,
) -> impl IntoView {
    let site_title = RwSignal::new(settings.site_title);
    let tagline = RwSignal::new(settings.tagline);
    let announcement = RwSignal::new(settings.announcement);
    let tos_url = RwSignal::new(settings.tos_url);
    let privacy_url = RwSignal::new(settings.privacy_url);
    let support_url = RwSignal::new(settings.support_url);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = (
                site_title.get(),
                tagline.get(),
                announcement.get(),
                tos_url.get(),
                privacy_url.get(),
                support_url.get(),
            );
        },
        pending,
        error,
    );
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
        let values = HashMap::from([
            ("site_title".to_string(), site_title.get_untracked()),
            ("tagline".to_string(), tagline.get_untracked()),
            ("announcement".to_string(), announcement.get_untracked()),
            ("tos_url".to_string(), tos_url.get_untracked()),
            ("privacy_url".to_string(), privacy_url.get_untracked()),
            ("support_url".to_string(), support_url.get_untracked()),
        ]);
        plan_settings(
            plan_client.clone(),
            "branding",
            values,
            version.clone(),
            pending,
            error,
            busy,
            draft_epoch,
        );
    };
    let on_apply = apply_settings(client, pending, error, busy);

    view! {
        <section class="panel editor-panel">
            <div class="section-heading"><div><p class="section-kicker">"Appearance"</p><h2>"Branding"</h2><p>"Set the public site identity, operator announcement, and links shown in Hub surfaces. Empty values use the built-in presentation or hide the optional item."</p></div></div>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Site title"</span><input prop:value=move || site_title.get() on:input=move |event| site_title.set(event_target_value(&event))/></label>
                <label><span>"Tagline"</span><input prop:value=move || tagline.get() on:input=move |event| tagline.set(event_target_value(&event))/></label>
                <label class="full-field"><span>"Announcement"</span><textarea prop:value=move || announcement.get() on:input=move |event| announcement.set(event_target_value(&event))></textarea></label>
                <label><span>"Terms URL"</span><input type="url" prop:value=move || tos_url.get() on:input=move |event| tos_url.set(event_target_value(&event))/></label>
                <label><span>"Privacy URL"</span><input type="url" prop:value=move || privacy_url.get() on:input=move |event| privacy_url.set(event_target_value(&event))/></label>
                <label><span>"Support URL"</span><input type="url" prop:value=move || support_url.get() on:input=move |event| support_url.set(event_target_value(&event))/></label>
                <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review branding"</button></div>
            </form>
            <SettingsReview pending=pending error=error busy=busy on_apply=on_apply/>
        </section>
    }
}

#[component]
fn SettingsReview(
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    on_apply: Callback<()>,
) -> impl IntoView {
    view! {
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
    }
}

fn plan_settings(
    client: ApiClient,
    action: &'static str,
    values: HashMap<String, String>,
    expected_resource_version: String,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    draft_epoch: RwSignal<u64>,
) {
    let planned_epoch = draft_epoch.get_untracked();
    pending.set(None);
    let idempotency_key = idempotency_key(action);
    let request = aos_proto_types::PlanSetInstanceSettingsRequest {
        values,
        clear: Vec::new(),
        expected_resource_version,
        idempotency_key: idempotency_key.clone(),
    };
    busy.set(true);
    error.set(None);
    spawn_local(async move {
        let result = client
            .call::<_, aos_proto_types::TopologyPlanResponse>(
                aos_proto_types::INSTANCE_SERVICE_PLAN_SET_INSTANCE_SETTINGS_PATH,
                &request,
            )
            .await
            .map_err(|failure| failure.to_string())
            .and_then(|response| PendingPlan::from_response(response, idempotency_key));
        match result {
            Ok(reviewed) if draft_epoch.get_untracked() == planned_epoch => {
                pending.set(Some(reviewed));
            }
            Ok(_) => {}
            Err(detail) => error.set(Some(detail)),
        }
        busy.set(false);
    });
}

fn apply_settings(
    client: ApiClient,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) -> Callback<()> {
    Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::GetInstanceSettingsResponse>(
                    aos_proto_types::INSTANCE_SERVICE_SET_INSTANCE_SETTINGS_PATH,
                    &reviewed.topology_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}

fn normalized_lines(value: &str) -> Vec<String> {
    let mut values = value
        .lines()
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_lowercase)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn non_negative(value: &str, field: &str) -> Result<String, String> {
    let parsed = value
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("{field} must be a non-negative integer"))?;
    if parsed < 0 {
        Err(format!("{field} must be a non-negative integer"))
    } else {
        Ok(parsed.to_string())
    }
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn signup_policy_label(value: &str) -> String {
    match value {
        "invite_only" => "Invite only".to_string(),
        "open" => "Open signup".to_string(),
        _ if value.is_empty() => "Hub default".to_string(),
        _ => value.replace('_', " "),
    }
}

fn crawl_policy_label(value: &str) -> String {
    match value {
        "allow_all" => "Allow all".to_string(),
        "allow_no_ai" => "Allow, excluding AI crawlers".to_string(),
        "deny_all" => "Deny all".to_string(),
        _ if value.is_empty() => "Hub default".to_string(),
        _ => value.replace('_', " "),
    }
}

fn enabled_disabled(value: bool) -> &'static str {
    if value {
        "Enabled"
    } else {
        "Disabled"
    }
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn reload() {
    crate::app::refresh();
}
