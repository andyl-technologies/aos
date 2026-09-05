//! Shared settings shell and browser application bootstrap.
//!
//! The shell owns one contextual heading, deterministic grouped navigation,
//! authenticated principal context, and a single content column. Resource
//! workflows plug into this shell without inventing their own hierarchy or
//! transport.

use leptos::ev;
use leptos::leptos_dom::helpers::{set_timeout, window_event_listener};
use leptos::prelude::*;
use wasm_bindgen::{JsCast, JsValue};

use aos_hub_console_contract::settings_navigation_starts_open;

use crate::route::{ConsoleRoute, ConsoleScope, PageSpec, AUTHENTICATED_PRIMARY_NAVIGATION};
use crate::transport::ApiClient;
use crate::workflows::ResourceWorkflow;

/// Mounts the closed management application for the current canonical path.
#[component]
pub fn App() -> impl IntoView {
    let route = RwSignal::new(current_route());
    let workflow_revision = RwSignal::new(0_u64);
    let navigate = Callback::new(move |path: String| {
        let Some(next_route) = ConsoleRoute::resolve(&path) else {
            return;
        };
        if route.get_untracked().as_ref() == Some(&next_route) {
            return;
        }
        let Some(window) = leptos::web_sys::window() else {
            return;
        };
        if window
            .history()
            .and_then(|history| history.push_state_with_url(&JsValue::NULL, "", Some(&path)))
            .is_err()
        {
            return;
        }
        if let Some(document) = window.document() {
            document.set_title(&format!("{} — AOS Hub", next_route.page.label));
        }
        window.scroll_to_with_x_and_y(0.0, 0.0);
        route.set(Some(next_route));
    });
    let popstate = window_event_listener(ev::popstate, move |_| {
        let next_route = current_route();
        if next_route == route.get_untracked() {
            workflow_revision.update(|revision| *revision = revision.wrapping_add(1));
        } else {
            route.set(next_route);
        }
    });
    on_cleanup(move || popstate.remove());
    let navigation_open = RwSignal::new(settings_navigation_starts_open(viewport_width()));
    let navigation_resize = window_event_listener(ev::resize, move |_| {
        navigation_open.set(settings_navigation_starts_open(viewport_width()));
    });
    on_cleanup(move || navigation_resize.remove());
    let csrf = shell_meta("aos-session-csrf").unwrap_or_default();
    let session_scope = Memo::new(move |_| {
        route
            .get()
            .map(|current_route| current_route.base_path.clone())
    });
    let session = LocalResource::new(move || {
        // Browser-session tokens carry permissions for one exact management
        // scope. Sibling settings pages share one permission set, so changing
        // only the page must not invalidate the session and replace the shell
        // with its loading fallback. Crossing a resource root still exchanges
        // a token for the new authorization scope.
        let _ = session_scope.get();
        let route = route
            .get_untracked()
            .map(|route| route.href(route.page))
            .unwrap_or_else(|| "/".to_string());
        let csrf = csrf.clone();
        async move { ApiClient::from_browser_session(&csrf, &route).await }
    });

    view! {
        <For
            each=move || route.get().into_iter()
            key=|route| route.href(route.page)
            children=move |route| {
                view! {
                    <ManagementShell
                        route=route
                        session=session
                        navigate=navigate
                        navigation_open=navigation_open
                        workflow_revision=workflow_revision
                    />
                }
            }
        />
        {move || route.get().is_none().then(|| view! {
                <main class="fatal-page">
                    <p class="eyebrow">"AOS Hub"</p>
                    <h1>"Unknown management route"</h1>
                    <p>"This path is not part of the closed control-plane route registry."</p>
                </main>
        })}
    }
}

#[component]
fn ManagementShell(
    route: ConsoleRoute,
    session: LocalResource<Result<ApiClient, crate::transport::TransportError>>,
    navigate: Callback<String>,
    navigation_open: RwSignal<bool>,
    workflow_revision: RwSignal<u64>,
) -> impl IntoView {
    let context = scope_title(&route.scope);
    let page_label = route.page.label;
    let navigation_route = route.clone();
    let context_route = route.clone();
    let workflow_route = route.clone();
    let brand = shell_meta("aos-site-brand").unwrap_or_else(|| "AOS Hub".to_string());
    let tagline = shell_meta("aos-site-tagline").unwrap_or_default();
    let announcement = shell_meta("aos-site-announcement").unwrap_or_default();
    let app_version = shell_meta("aos-app-version").unwrap_or_else(|| "aos-hub".to_string());
    let footer_links = [
        ("terms", shell_meta("aos-site-tos-url")),
        ("privacy", shell_meta("aos-site-privacy-url")),
        ("support", shell_meta("aos-site-support-url")),
    ]
    .into_iter()
    .filter_map(|(label, href)| {
        href.filter(|href| !href.is_empty())
            .map(|href| (label, href))
    })
    .collect::<Vec<_>>();
    let on_console_link = move |event: ev::MouseEvent| {
        if event.default_prevented()
            || event.button() != 0
            || event.alt_key()
            || event.ctrl_key()
            || event.meta_key()
            || event.shift_key()
        {
            return;
        }
        let Some(target) = event
            .target()
            .and_then(|target| target.dyn_into::<leptos::web_sys::Element>().ok())
        else {
            return;
        };
        let Ok(Some(anchor)) = target.closest("a[href]") else {
            return;
        };
        if anchor.has_attribute("download") || anchor.has_attribute("target") {
            return;
        }
        let Some(path) = anchor.get_attribute("href") else {
            return;
        };
        if !path.starts_with('/')
            || path.starts_with("//")
            || ConsoleRoute::resolve(&path).is_none()
        {
            return;
        }
        event.prevent_default();
        navigate.run(path);
    };

    view! {
        <div class="app-shell" on:click=on_console_link>
            <a class="skip-link" href="#main-content">"Skip to content"</a>
            <header class="masthead">
                <a class="brand" href="/">{brand}</a>
                {(!tagline.is_empty()).then(|| view! { <span class="tagline">{tagline}</span> })}
                <span class="crumbs">
                    <a href=route.base_path.clone()>{context.clone()}</a>
                    " / "
                    {page_label}
                </span>
                <span class="session">
                    {AUTHENTICATED_PRIMARY_NAVIGATION.iter().enumerate().map(|(index, item)| view! {
                        {(index > 0).then_some(" · ")}
                        <a href=item.href>{item.label}</a>
                    }).collect_view()}
                    " · "
                    <span class="who"><Suspense fallback=move || "signed-in user">{move || Suspend::new(async move { session.await.as_ref().ok().and_then(|client| client.session().principal.map(|principal| principal.email)).unwrap_or_else(|| "signed-in user".to_string()) })}</Suspense></span>
                    " · "
                    <a href="/logout">"log out"</a>
                </span>
            </header>
            {(!announcement.is_empty()).then(|| view! { <div class="announce">{announcement}</div> })}
            <div class="settings">
                <details
                    class="settings-nav-disclosure"
                    open=move || navigation_open.get()
                    on:toggle=move |event| {
                        let open = event
                            .target()
                            .and_then(|target| target.dyn_into::<leptos::web_sys::Element>().ok())
                            .is_some_and(|details| details.has_attribute("open"));
                        navigation_open.set(open);
                    }
                >
                    <summary>"Settings navigation"</summary>
                    <Transition fallback=move || view! { <nav class="settings-nav" aria-label="Settings navigation" aria-busy="true"><span class="settings-nav-label">"Loading navigation…"</span></nav> }>
                        {move || { let route = navigation_route.clone(); Suspend::new(async move { match session.await.as_ref() { Ok(client) => view! { <Navigation route=route client=client.clone()/> }.into_any(), Err(_) => view! { <nav class="settings-nav" aria-label="Settings navigation"><a href=route.base_path.clone()>"Overview"</a></nav> }.into_any() } }) }}
                    </Transition>
                </details>
                <main id="main-content" class="settings-body">
                    <ScopeHeader route=route.clone()/>
                    <ContextRail route=context_route.clone()/>
                    <For
                        each=move || vec![workflow_revision.get()]
                        key=|revision| *revision
                        children=move |_| {
                            let route = workflow_route.clone();
                            view! {
                                <Transition fallback=move || view! { <p class="loading-row" aria-busy="true">"Loading management data…"</p> }>
                                    {move || { let route = route.clone(); Suspend::new(async move { match session.await.as_ref() { Ok(client) if client.allows(route.page.navigation_permission()) => view! { <ResourceWorkflow route=route client=client.clone()/> }.into_any(), Ok(_) => view! { <PermissionDenied route=route/> }.into_any(), Err(error) => view! { <FailureShell route=route detail=error.to_string()/> }.into_any() } }) }}
                                </Transition>
                            }
                        }
                    />
                </main>
            </div>
            <footer class="statline">
                {app_version}
                {(!footer_links.is_empty()).then(|| view! {
                    <span class="footer-links">
                        {footer_links.into_iter().enumerate().map(|(index, (label, href))| view! {
                            {(index > 0).then_some(" · ")}
                            <a href=href>{label}</a>
                        }).collect_view()}
                    </span>
                })}
            </footer>
        </div>
    }
}

#[component]
fn ScopeHeader(route: ConsoleRoute) -> impl IntoView {
    let kind = scope_kind(&route.scope);
    let identity = scope_identity(&route.scope);
    let overview = route.base_path.clone();

    view! {
        <header class="scope-header">
            <div>
                <p class="section-kicker">{format!("{kind} settings")}</p>
                <h1>{route.page.label}</h1>
                <p class="scope-identity"><span>"Scope"</span><strong>{identity}</strong></p>
            </div>
            {(route.page.key != "overview").then(|| view! { <a href=overview>"View scope overview"</a> })}
        </header>
    }
}

#[component]
fn ContextRail(route: ConsoleRoute) -> impl IntoView {
    let visible = matches!(route.page.group, "Infrastructure" | "Topology")
        || matches!(route.page.key, "integrations" | "retention" | "gc");
    visible.then(|| {
        let edges = related_settings(&route);
        view! {
            <details class="topology-context">
                <summary>"Related settings"</summary>
                <ContextEdges label="Configuration areas" edges=edges/>
            </details>
        }
    })
}

#[component]
fn ContextEdges(label: &'static str, edges: Vec<(&'static str, String)>) -> impl IntoView {
    view! {
        <section class="context-edges">
            <h2>{label}</h2>
            {if edges.is_empty() {
                view! { <p>"None at this scope"</p> }.into_any()
            } else {
                view! { <ul>{edges.into_iter().map(|(name, href)| view! {
                    <li><a href=href>{name}</a></li>
                }).collect_view()}</ul> }.into_any()
            }}
        </section>
    }
}

fn related_settings(route: &ConsoleRoute) -> Vec<(&'static str, String)> {
    let sibling = |suffix: &str| format!("{}/{suffix}", route.base_path);
    match &route.scope {
        ConsoleScope::Registry { .. } => vec![
            ("Placements", sibling("placements")),
            ("Delivery", sibling("delivery")),
            ("Binary caches", sibling("caches")),
        ],
        ConsoleScope::Cache { .. } => vec![
            ("Placements", sibling("placements")),
            ("Delivery", sibling("delivery")),
            ("Registry integrations", sibling("integrations")),
        ],
        ConsoleScope::Organization { .. } => vec![
            ("Bindings", sibling("bindings")),
            ("Endpoints", sibling("endpoints")),
            ("Gateways", sibling("gateways")),
            ("Registries", sibling("registries")),
            ("Binary caches", sibling("caches")),
        ],
        ConsoleScope::Instance => vec![
            ("Bindings", sibling("bindings")),
            ("Endpoints", sibling("endpoints")),
            ("Gateways", sibling("gateways")),
            ("Organizations", "/-/orgs".to_string()),
        ],
        ConsoleScope::Caches | ConsoleScope::Organizations => Vec::new(),
    }
}

#[component]
fn Navigation(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    let groups = navigation_groups(&route, &client);
    view! {
        <nav class="settings-nav" aria-label="Settings navigation">
            {groups.into_iter().map(|group| {
                let heading = (!group.label.is_empty()).then_some(group.label);
                view! {
                    <div class="settings-nav-group">
                        {heading.map(|label| view! { <span class="settings-nav-label">{label}</span> })}
                        {group.pages.into_iter().map(|page| {
                            let current = page.key == route.page.key;
                            view! {
                                <a aria-current=current.then_some("page") href=route.href(page)>
                                    {page.label}
                                </a>
                            }
                        }).collect_view()}
                    </div>
                }
            }).collect_view()}
        </nav>
    }
}

#[component]
fn FailureShell(route: ConsoleRoute, detail: String) -> impl IntoView {
    view! {
        <section class="workflow-message">
            <p class="eyebrow">{scope_title(&route.scope)}</p>
            <h1>"Management session unavailable"</h1>
            <p>{detail}</p>
            <a class="button" href="/login">"Sign in again"</a>
        </section>
    }
}

#[component]
fn PermissionDenied(route: ConsoleRoute) -> impl IntoView {
    view! {
        <section class="workflow-message">
            <p class="eyebrow">{scope_title(&route.scope)}</p>
            <h1>"Permission required"</h1>
            <p>"Your current live grants do not permit this management page."</p>
            <a class="button" href=route.base_path>"Return to overview"</a>
        </section>
    }
}

#[derive(Debug)]
struct NavigationGroup {
    label: &'static str,
    pages: Vec<&'static PageSpec>,
}

fn navigation_groups(route: &ConsoleRoute, client: &ApiClient) -> Vec<NavigationGroup> {
    let mut groups = Vec::<NavigationGroup>::new();
    let permissions = client.session().route_permissions;
    for page in route.visible_navigation(&permissions) {
        match groups.last_mut() {
            Some(group) if group.label == page.group => group.pages.push(page),
            _ => groups.push(NavigationGroup {
                label: page.group,
                pages: vec![page],
            }),
        }
    }
    groups
}

/// Navigates to one canonical management route without replacing the document.
///
/// Mutation workflows use this path after a successful apply so the mounted
/// application chrome and in-memory browser session survive. Dispatching a
/// synthetic `popstate` event drives the same route refresh as browser
/// back/forward navigation. The dispatch runs in the next browser task so the
/// mutation callback can finish its terminal reactive updates before unmount.
pub(crate) fn navigate(path: &str) {
    let Some(route) = ConsoleRoute::resolve(path) else {
        return;
    };
    let Some(window) = leptos::web_sys::window() else {
        return;
    };
    let pushed = window
        .history()
        .and_then(|history| history.push_state_with_url(&JsValue::NULL, "", Some(path)))
        .is_ok();
    if !pushed {
        let _ = window.location().set_href(path);
        return;
    }
    if let Some(document) = window.document() {
        document.set_title(&format!("{} — AOS Hub", route.page.label));
    }
    window.scroll_to_with_x_and_y(0.0, 0.0);
    let fallback_path = path.to_string();
    set_timeout(
        move || match leptos::web_sys::PopStateEvent::new("popstate") {
            Ok(event) => {
                let _ = window.dispatch_event(&event);
            }
            Err(_) => {
                let _ = window.location().set_href(&fallback_path);
            }
        },
        std::time::Duration::ZERO,
    );
}

/// Refreshes the active workflow without unloading the management application.
///
/// The refresh runs in the next browser task. Mutation callbacks and their
/// queued reactive updates can therefore finish before the workflow subtree
/// is disposed and mounted again.
pub(crate) fn refresh() {
    set_timeout(
        || {
            let Some(window) = leptos::web_sys::window() else {
                return;
            };
            match leptos::web_sys::PopStateEvent::new("popstate") {
                Ok(event) => {
                    let _ = window.dispatch_event(&event);
                }
                Err(_) => {
                    let _ = window.location().reload();
                }
            }
        },
        std::time::Duration::ZERO,
    );
}

fn current_route() -> Option<ConsoleRoute> {
    let path = leptos::web_sys::window()?.location().pathname().ok()?;
    ConsoleRoute::resolve(&path)
}

fn shell_meta(name: &str) -> Option<String> {
    let document = leptos::web_sys::window()?.document()?;
    document
        .query_selector(&format!("meta[name='{name}']"))
        .ok()??
        .get_attribute("content")
}

/// Returns whether the authenticated shell explicitly advertises one feature.
///
/// Missing metadata means unavailable, so rollout-gated controls remain
/// fail-closed when an older shell cannot make the server capability known.
pub(crate) fn shell_feature(name: &str) -> bool {
    shell_meta(name).is_some_and(|value| value == "true")
}

fn scope_title(scope: &ConsoleScope) -> String {
    match scope {
        ConsoleScope::Instance => "Settings".to_string(),
        ConsoleScope::Caches => "Caches".to_string(),
        ConsoleScope::Organizations => "Organizations".to_string(),
        ConsoleScope::Organization { slug } => slug.clone(),
        ConsoleScope::Registry { path } => path.clone(),
        ConsoleScope::Cache { path } => path.clone(),
    }
}

fn scope_kind(scope: &ConsoleScope) -> &'static str {
    match scope {
        ConsoleScope::Instance => "Instance",
        ConsoleScope::Caches => "Cache inventory",
        ConsoleScope::Organizations => "Organization inventory",
        ConsoleScope::Organization { .. } => "Organization",
        ConsoleScope::Registry { .. } => "Registry",
        ConsoleScope::Cache { .. } => "Binary cache",
    }
}

fn scope_identity(scope: &ConsoleScope) -> String {
    match scope {
        ConsoleScope::Instance => "AOS Hub deployment".to_string(),
        ConsoleScope::Caches => "All visible caches".to_string(),
        ConsoleScope::Organizations => "All visible organizations".to_string(),
        ConsoleScope::Organization { slug }
        | ConsoleScope::Registry { path: slug }
        | ConsoleScope::Cache { path: slug } => slug.clone(),
    }
}

fn viewport_width() -> Option<f64> {
    leptos::web_sys::window()?.inner_width().ok()?.as_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_preserves_first_page_and_group_boundaries() {
        let route = ConsoleRoute::resolve("/-/org/acme/members").expect("route must resolve");
        let session = aos_proto_types::BrowserSessionTokenResponse {
            route_permissions: vec!["read".to_string(), "tokens.self".to_string()],
            ..Default::default()
        };
        let client = ApiClient::for_test(session);
        let groups = navigation_groups(&route, &client);
        assert_eq!(groups[0].pages[0].key, "overview");
        assert_eq!(groups[1].label, "Resources");
        assert_eq!(groups[2].label, "Infrastructure");
        assert_eq!(groups[3].label, "Access & trust");
        let keys = groups
            .iter()
            .flat_map(|group| group.pages.iter().map(|page| page.key))
            .collect::<Vec<_>>();
        assert!(keys.contains(&"tokens"));
        assert!(!keys.contains(&"sso"));
        assert!(!keys.contains(&"audit"));
        assert!(!keys.contains(&"danger"));
    }

    #[test]
    fn related_settings_use_canonical_links_without_claiming_resource_relationships() {
        let registry = ConsoleRoute::resolve("/acme/main/-/settings/placements")
            .expect("registry topology route");
        let registry_links = related_settings(&registry);
        assert_eq!(registry_links[0].1, "/acme/main/-/settings/placements");
        assert_eq!(registry_links[2].1, "/acme/main/-/settings/caches");

        let cache = ConsoleRoute::resolve("/-/org/acme/caches/build/delivery")
            .expect("cache topology route");
        let cache_links = related_settings(&cache);
        assert_eq!(cache_links[2].1, "/-/org/acme/caches/build/integrations");
    }

    #[test]
    fn scope_header_names_resource_kind_and_exact_identity() {
        let route = ConsoleRoute::resolve("/acme/main/-/settings/delivery")
            .expect("registry delivery route");
        assert_eq!(scope_kind(&route.scope), "Registry");
        assert_eq!(scope_identity(&route.scope), "acme/main");
    }

    #[test]
    fn stylesheet_extends_the_shared_paper_design_without_replacing_it() {
        let css = include_str!("../assets/app.css");
        assert!(css.contains("var(--paper)"));
        assert!(css.contains("var(--rule)"));
        assert!(css.contains("var(--form-label-col)"));
        assert!(css.contains("@media (max-width: 48rem)"));
        for forbidden in [
            ":root",
            "color-scheme:",
            "--canvas:",
            "font-family: system-ui",
            "box-shadow:",
            "backdrop-filter:",
        ] {
            assert!(
                !css.contains(forbidden),
                "supplemental console CSS redefines the shared design with {forbidden}"
            );
        }
    }

    #[test]
    fn masthead_exposes_instance_settings() {
        let settings = AUTHENTICATED_PRIMARY_NAVIGATION
            .iter()
            .find(|item| item.href == "/-/instance")
            .expect("settings navigation item");
        assert_eq!(settings.label, "settings");
    }
}
