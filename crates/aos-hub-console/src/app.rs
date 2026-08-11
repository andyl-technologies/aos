//! Shared settings shell and browser application bootstrap.
//!
//! The shell owns one contextual heading, deterministic grouped navigation,
//! authenticated principal context, and a single content column. Resource
//! workflows plug into this shell without inventing their own hierarchy or
//! transport.

use leptos::ev;
use leptos::leptos_dom::helpers::window_event_listener;
use leptos::prelude::*;
use wasm_bindgen::{JsCast, JsValue};

use crate::route::{ConsoleRoute, ConsoleScope, PageSpec};
use crate::transport::ApiClient;
use crate::workflows::ResourceWorkflow;

/// Mounts the closed management application for the current canonical path.
#[component]
pub fn App() -> impl IntoView {
    let route = RwSignal::new(current_route());
    let navigate = Callback::new(move |path: String| {
        let Some(next_route) = ConsoleRoute::resolve(&path) else {
            return;
        };
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
    let popstate = window_event_listener(ev::popstate, move |_| route.set(current_route()));
    on_cleanup(move || popstate.remove());
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
        let csrf = csrf.clone();
        async move { ApiClient::from_browser_session(&csrf).await }
    });

    view! {
        {move || match route.get() {
            Some(route) => {
                let fallback_route = route.clone();
                view! {
                    <Transition fallback=move || view! { <LoadingShell route=fallback_route.clone()/> }>
                        {move || {
                            let route = route.clone();
                            Suspend::new(async move {
                                match session.await.as_ref() {
                                    Ok(client) if client.allows(route.page.navigation_permission()) => view! {
                                        <ManagementShell route=route client=client.clone() navigate=navigate/>
                                    }.into_any(),
                                    Ok(_) => view! {
                                        <PermissionDenied route=route/>
                                    }.into_any(),
                                    Err(error) => view! {
                                        <FailureShell route=route detail=error.to_string()/>
                                    }.into_any(),
                                }
                            })
                        }}
                    </Transition>
                }.into_any()
            },
            None => view! {
                <main class="fatal-page">
                    <p class="eyebrow">"AOS Hub"</p>
                    <h1>"Unknown management route"</h1>
                    <p>"This path is not part of the closed control-plane route registry."</p>
                </main>
            }.into_any(),
        }}
    }
}

#[component]
fn ManagementShell(
    route: ConsoleRoute,
    client: ApiClient,
    navigate: Callback<String>,
) -> impl IntoView {
    let principal = client
        .session()
        .principal
        .as_ref()
        .map(|principal| principal.email.clone())
        .unwrap_or_else(|| "signed-in user".to_string());
    let context = scope_title(&route.scope);
    let page_label = route.page.label;
    let workflow_route = route.clone();
    let brand = shell_meta("aos-site-brand").unwrap_or_else(|| "AOS Hub".to_string());
    let tagline = shell_meta("aos-site-tagline").unwrap_or_default();
    let announcement = shell_meta("aos-site-announcement").unwrap_or_default();
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
                    <a href="/">"registries"</a>
                    " · "
                    <a href="/-/caches">"caches"</a>
                    " · "
                    <a href="/-/orgs">"organizations"</a>
                    " · "
                    <a href="/-/account">"account"</a>
                    " · "
                    <span class="who">{principal}</span>
                    " · "
                    <a href="/logout">"log out"</a>
                </span>
            </header>
            {(!announcement.is_empty()).then(|| view! { <div class="announce">{announcement}</div> })}
            <div class="settings">
                <details class="settings-nav-disclosure" open>
                    <summary>"Settings navigation"</summary>
                    <Navigation route=route.clone() client=client.clone()/>
                </details>
                <main id="main-content" class="settings-body">
                    <h1>{page_label}</h1>
                    <ContextRail route=route.clone()/>
                    <ResourceWorkflow route=workflow_route client=client/>
                </main>
            </div>
            {(!footer_links.is_empty()).then(|| view! {
                <footer class="statline">
                    <span class="footer-links">
                        {footer_links.into_iter().enumerate().map(|(index, (label, href))| view! {
                            {(index > 0).then_some(" · ")}
                            <a href=href>{label}</a>
                        }).collect_view()}
                    </span>
                </footer>
            })}
        </div>
    }
}

#[component]
fn ContextRail(route: ConsoleRoute) -> impl IntoView {
    let visible = matches!(route.page.group, "Infrastructure" | "Topology")
        || matches!(route.page.key, "integrations" | "retention" | "gc");
    visible.then(|| {
        let (owns, uses, used_by) = topology_context(&route);
        view! {
            <details class="topology-context">
                <summary>"Topology context"</summary>
                <div class="topology-context-grid">
                    <ContextEdges label="Owns" edges=owns/>
                    <ContextEdges label="Uses" edges=uses/>
                    <ContextEdges label="Used by" edges=used_by/>
                </div>
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

fn topology_context(
    route: &ConsoleRoute,
) -> (
    Vec<(&'static str, String)>,
    Vec<(&'static str, String)>,
    Vec<(&'static str, String)>,
) {
    let sibling = |suffix: &str| format!("{}/{suffix}", route.base_path);
    match &route.scope {
        ConsoleScope::Registry { .. } => (
            vec![
                ("Placements", sibling("placements")),
                ("Delivery routes", sibling("delivery")),
            ],
            vec![("Binary caches", sibling("caches"))],
            Vec::new(),
        ),
        ConsoleScope::Cache { .. } => (
            vec![
                ("Placements", sibling("placements")),
                ("Delivery routes", sibling("delivery")),
            ],
            Vec::new(),
            vec![("Registry integrations", sibling("integrations"))],
        ),
        ConsoleScope::Organization { .. } => (
            vec![
                ("Storage bindings", sibling("storage-bindings")),
                ("Delivery endpoints", sibling("delivery-endpoints")),
            ],
            Vec::new(),
            vec![
                ("Registries", sibling("registries")),
                ("Binary caches", sibling("caches")),
            ],
        ),
        ConsoleScope::Instance => (
            vec![
                ("Storage bindings", sibling("storage-bindings")),
                ("Delivery endpoints", sibling("delivery-endpoints")),
            ],
            Vec::new(),
            vec![("Organizations", "/-/orgs".to_string())],
        ),
        ConsoleScope::Caches => (Vec::new(), Vec::new(), Vec::new()),
        ConsoleScope::Organizations => (Vec::new(), Vec::new(), Vec::new()),
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
fn LoadingShell(route: ConsoleRoute) -> impl IntoView {
    view! {
        <main class="fatal-page" aria-busy="true">
            <p class="eyebrow">{scope_title(&route.scope)}</p>
            <h1>{route.page.label}</h1>
            <p>"Establishing a short-lived management session…"</p>
        </main>
    }
}

#[component]
fn FailureShell(route: ConsoleRoute, detail: String) -> impl IntoView {
    view! {
        <main class="fatal-page">
            <p class="eyebrow">{scope_title(&route.scope)}</p>
            <h1>"Management session unavailable"</h1>
            <p>{detail}</p>
            <a class="button" href="/login">"Sign in again"</a>
        </main>
    }
}

#[component]
fn PermissionDenied(route: ConsoleRoute) -> impl IntoView {
    view! {
        <main class="fatal-page">
            <p class="eyebrow">{scope_title(&route.scope)}</p>
            <h1>"Permission required"</h1>
            <p>"Your current live grants do not permit this management page."</p>
            <a class="button" href=route.base_path>"Return to overview"</a>
        </main>
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

fn scope_title(scope: &ConsoleScope) -> String {
    match scope {
        ConsoleScope::Instance => "Hub settings".to_string(),
        ConsoleScope::Caches => "Caches".to_string(),
        ConsoleScope::Organizations => "Organizations".to_string(),
        ConsoleScope::Organization { slug } => slug.clone(),
        ConsoleScope::Registry { path } => path.clone(),
        ConsoleScope::Cache { path } => path.clone(),
    }
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
    fn topology_context_uses_relationship_labels_and_canonical_links() {
        let registry = ConsoleRoute::resolve("/acme/main/-/settings/placements")
            .expect("registry topology route");
        let (owns, uses, used_by) = topology_context(&registry);
        assert_eq!(owns[0].1, "/acme/main/-/settings/placements");
        assert_eq!(uses[0].1, "/acme/main/-/settings/caches");
        assert!(used_by.is_empty());

        let cache = ConsoleRoute::resolve("/-/org/acme/caches/build/delivery")
            .expect("cache topology route");
        let (_, _, used_by) = topology_context(&cache);
        assert_eq!(used_by[0].1, "/-/org/acme/caches/build/integrations");
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
}
