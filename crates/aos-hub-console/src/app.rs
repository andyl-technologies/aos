//! Shared settings shell and browser application bootstrap.
//!
//! The shell owns one contextual heading, deterministic grouped navigation,
//! authenticated principal context, and a single content column. Resource
//! workflows plug into this shell without inventing their own hierarchy or
//! transport.

use leptos::prelude::*;

use crate::route::{ConsoleRoute, ConsoleScope, PageSpec};
use crate::transport::ApiClient;
use crate::workflows::ResourceWorkflow;

/// Mounts the closed management application for the current canonical path.
#[component]
pub fn App() -> impl IntoView {
    let route = current_route();
    let csrf = shell_meta("aos-session-csrf").unwrap_or_default();
    let session = LocalResource::new(move || {
        let csrf = csrf.clone();
        async move { ApiClient::from_browser_session(&csrf).await }
    });

    view! {
        {match route {
            Some(route) => {
                let fallback_route = route.clone();
                view! {
                    <Suspense fallback=move || view! { <LoadingShell route=fallback_route.clone()/> }>
                        {move || {
                            let route = route.clone();
                            Suspend::new(async move {
                                match session.await.as_ref() {
                                    Ok(client) => view! {
                                        <ManagementShell route=route client=client.clone()/>
                                    }.into_any(),
                                    Err(error) => view! {
                                        <FailureShell route=route detail=error.to_string()/>
                                    }.into_any(),
                                }
                            })
                        }}
                    </Suspense>
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
fn ManagementShell(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    let principal = client
        .session()
        .principal
        .as_ref()
        .map(|principal| principal.email.clone())
        .unwrap_or_else(|| "signed-in user".to_string());
    let context = scope_title(&route.scope);
    let page_label = route.page.label;

    view! {
        <div class="app-shell">
            <header class="topbar">
                <a class="wordmark" href="/">"ANDYL" <span>"/ AOS Hub"</span></a>
                <div class="principal">
                    <span class="status-dot" aria-hidden="true"></span>
                    <span>{principal}</span>
                    <a href="/-/account">"Account"</a>
                </div>
            </header>
            <div class="workspace">
                <aside class="settings-sidebar" aria-label="Settings navigation">
                    <div class="scope-context">
                        <span class="eyebrow">{scope_kind(&route.scope)}</span>
                        <strong>{context.clone()}</strong>
                    </div>
                    <Navigation route=route.clone()/>
                </aside>
                <main class="content">
                    <header class="page-heading">
                        <div>
                            <p class="eyebrow">{context}</p>
                            <h1>{page_label}</h1>
                        </div>
                        <span class="workflow-chip">{route.page.workflow}</span>
                    </header>
                    <section class="panel intro-panel">
                        <div>
                            <p class="section-kicker">"Control plane"</p>
                            <h2>{page_label}</h2>
                            <p class="lede">
                                "This canonical page uses the same typed API and reviewed mutation contract as the CLI."
                            </p>
                        </div>
                        <div class="contract-card">
                            <span>"Workflow"</span>
                            <code>{route.page.workflow}</code>
                            <span>"Transport"</span>
                            <strong>"Connect / ProtoJSON"</strong>
                        </div>
                    </section>
                    <ResourceWorkflow route=route client=client/>
                </main>
            </div>
        </div>
    }
}

#[component]
fn Navigation(route: ConsoleRoute) -> impl IntoView {
    let groups = navigation_groups(&route);
    view! {
        <nav>
            {groups.into_iter().map(|group| {
                let heading = (!group.label.is_empty()).then_some(group.label);
                view! {
                    <div class="nav-group">
                        {heading.map(|label| view! { <p>{label}</p> })}
                        {group.pages.into_iter().map(|page| {
                            let current = page.key == route.page.key;
                            let class = if current { "nav-link current" } else { "nav-link" };
                            view! {
                                <a class=class aria-current=current.then_some("page") href=route.href(page)>
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

#[derive(Debug)]
struct NavigationGroup {
    label: &'static str,
    pages: Vec<&'static PageSpec>,
}

fn navigation_groups(route: &ConsoleRoute) -> Vec<NavigationGroup> {
    let mut groups = Vec::<NavigationGroup>::new();
    for page in route
        .navigation()
        .iter()
        .filter(|page| page.is_navigation_item())
    {
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

fn scope_kind(scope: &ConsoleScope) -> &'static str {
    match scope {
        ConsoleScope::Instance => "Instance",
        ConsoleScope::Organizations => "Directory",
        ConsoleScope::Organization { .. } => "Organization",
        ConsoleScope::Registry { .. } => "Registry",
        ConsoleScope::Cache { .. } => "Binary cache",
    }
}

fn scope_title(scope: &ConsoleScope) -> String {
    match scope {
        ConsoleScope::Instance => "Hub settings".to_string(),
        ConsoleScope::Organizations => "Organizations".to_string(),
        ConsoleScope::Organization { slug } => slug.clone(),
        ConsoleScope::Registry { path } => path.clone(),
        ConsoleScope::Cache {
            organization,
            cache,
        } => format!("{organization}/{cache}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_preserves_first_page_and_group_boundaries() {
        let route = ConsoleRoute::resolve("/-/org/acme/members").expect("route must resolve");
        let groups = navigation_groups(&route);
        assert_eq!(groups[0].pages[0].key, "overview");
        assert_eq!(groups[1].label, "Resources");
        assert_eq!(groups[2].label, "Infrastructure");
        assert_eq!(groups[3].label, "Access & trust");
    }
}
