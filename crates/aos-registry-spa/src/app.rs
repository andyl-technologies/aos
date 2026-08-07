//! The Leptos client-side-rendered application.
//!
//! [`App`] is the root component the SPA mounts over the static
//! `index.html` body. It progressively enhances the no-JS floor:
//!
//! - loads `web/config.json` (branding + optional `hub_url`) and
//!   `web/index.json` (registry meta + package list) same-origin,
//! - renders the registry home (description, package table, a search box),
//! - routes to a per-package view backed by `web/packages/<name>.json`,
//! - and offers a lazy "verify in your browser" badge that runs the real
//!   client-side verifier ([`crate::verify`]).
//!
//! Search uses the hub's `PackageService/ListPackages` over Connect-JSON
//! when `config.json` carries a `hub_url`, and degrades to a client-side
//! substring filter over `index.json` when it does not.

use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::closure::{build_closure_view, ClosureNode};
use crate::model::{Config, IndexSnapshot, PackageSnapshot};
use crate::net::{self, BrowserFetch};
use crate::verify::{verify_channel, BadgeOutcome};

/// Bundled stylesheet for the SPA, in the release-engineering-paper
/// aesthetic shared with the hub's server-rendered pages. Trunk copies this
/// to a hash-named `style-<hash>.css`; it is also inlined into the WASM via
/// `include_str!` so the SPA can theme even before the CSS link resolves.
pub const STYLE_CSS: &str = include_str!("../assets/app.css");

/// The root SPA component.
///
/// Loads the two same-origin snapshots once on mount, then renders either
/// the registry home or — when the document path is `/browse/<name>` or
/// `/browse/<name>.html` — the matching package view, so the SPA owns the
/// exact URLs the static pages occupy.
#[component]
pub fn App() -> impl IntoView {
    // config.json and index.json: loaded once, shared by every view.
    let config = LocalResource::new(|| async {
        net::get_json::<Config>("web/config.json")
            .await
            .unwrap_or_default()
    });
    let index = LocalResource::new(|| async {
        net::get_json::<IndexSnapshot>("web/index.json")
            .await
            .map_err(|err| format!("{err:#}"))
    });

    view! {
        <style>{STYLE_CSS}</style>
        <Suspense fallback=move || view! { <p class="dim">"Loading registry…"</p> }>
            {move || Suspend::new(async move {
                let cfg = config.await;
                let idx = index.await;
                match idx {
                    Ok(idx) => view! { <Surface config=cfg index=idx/> }.into_any(),
                    Err(err) => view! {
                        <p class="bad">"Could not load registry snapshot: " {err}</p>
                    }
                    .into_any(),
                }
            })}
        </Suspense>
    }
}

/// The loaded registry surface: routes to home or a package view by the
/// current document path.
#[component]
fn Surface(config: Config, index: IndexSnapshot) -> impl IntoView {
    let package = current_browse_package();
    match package {
        Some(name) => view! { <PackageView name=name registry=config.name.clone()/> }.into_any(),
        None => view! { <Home config=config index=index/> }.into_any(),
    }
}

/// The registry home: masthead, description, search, package table, and the
/// in-browser verification badge.
#[component]
fn Home(config: Config, index: IndexSnapshot) -> impl IntoView {
    let registry_name = config.name.clone();
    let hub_url = config.hub_url.clone();
    let packages = index.packages.clone();

    // Search query and its filtered result names. Hub search (when wired)
    // replaces the names; otherwise we substring-filter the snapshot.
    let (query, set_query) = signal(String::new());
    let (hub_names, set_hub_names) = signal::<Option<Vec<String>>>(None);

    let on_search = {
        let hub_url = hub_url.clone();
        move |_| {
            let q = query.get();
            let Some(hub) = hub_url.clone() else { return };
            if q.is_empty() {
                set_hub_names.set(None);
                return;
            }
            spawn_local(async move {
                match net::hub_list_packages(&hub, &q).await {
                    Ok(value) => set_hub_names.set(Some(extract_package_names(&value))),
                    // Degrade silently to the client-side filter on hub error.
                    Err(_) => set_hub_names.set(None),
                }
            });
        }
    };

    // A reactive memo (Copy) so both the count header and the table body
    // can read the filtered list without a closure-move conflict.
    let filtered = Memo::new(move |_| {
        let q = query.get().to_lowercase();
        if let Some(names) = hub_names.get() {
            packages
                .iter()
                .filter(|pkg| names.contains(&pkg.name))
                .cloned()
                .collect::<Vec<_>>()
        } else if q.is_empty() {
            packages.clone()
        } else {
            packages
                .iter()
                .filter(|pkg| {
                    pkg.name.to_lowercase().contains(&q)
                        || pkg.description.to_lowercase().contains(&q)
                })
                .cloned()
                .collect::<Vec<_>>()
        }
    });

    let has_hub = hub_url.is_some();
    let generated = index.generated_at.clone();
    let generator = index.generator.clone();

    view! {
        <header class="masthead">
            <span class="brand">{registry_name.clone()}</span>
            <span class="crumbs">"web surface"</span>
        </header>
        <h1>{registry_name.clone()}</h1>
        {(!index.description.is_empty()).then(|| view! { <p>{index.description.clone()}</p> })}

        <VerifyBadge/>

        <h2>"Search"</h2>
        <form class="console" on:submit=move |ev| { ev.prevent_default(); }>
            <input
                type="text"
                placeholder=if has_hub { "search the hub…" } else { "filter packages…" }
                on:input=move |ev| set_query.set(event_target_value(&ev))
                prop:value=move || query.get()
            />
            {has_hub.then(|| view! {
                <button type="button" on:click=on_search>"Search hub"</button>
            })}
        </form>

        <h2>{move || format!("Packages ({})", filtered.get().len())}</h2>
        <table>
            <tr><th>"Package"</th><th>"Version"</th><th>"License"</th><th>"Description"</th></tr>
            <For
                each=move || filtered.get()
                key=|pkg| pkg.name.clone()
                children=move |pkg| {
                    let href = format!("browse/{}.html", pkg.name);
                    view! {
                        <tr>
                            <td><a href=href>{pkg.name.clone()}</a></td>
                            <td>{pkg.latest_version.clone()}</td>
                            <td>{pkg.license.clone()}</td>
                            <td>{pkg.description.clone()}</td>
                        </tr>
                    }
                }
            />
        </table>

        <p class="statline">
            "Snapshot by " {generator} " — generated " {generated} ". "
            "This page is a client-side enhancement of the same static URL "
            "curl and lynx see."
        </p>
    }
}

/// The per-package view, backed by `web/packages/<name>.json`.
#[component]
fn PackageView(name: String, registry: String) -> impl IntoView {
    let path = format!("web/packages/{name}.json");
    let snapshot = LocalResource::new(move || {
        let path = path.clone();
        async move {
            net::get_json::<PackageSnapshot>(&path)
                .await
                .map_err(|err| format!("{err:#}"))
        }
    });

    view! {
        <header class="masthead">
            <span class="brand">{registry.clone()}</span>
            <span class="crumbs"><a href="index.html">"← registry"</a></span>
        </header>
        <Suspense fallback=move || view! { <p class="dim">"Loading package…"</p> }>
            {move || Suspend::new(async move {
                match snapshot.await {
                    Ok(pkg) => view! { <PackageBody pkg=pkg/> }.into_any(),
                    Err(err) => view! {
                        <p class="bad">"Could not load package: " {err}</p>
                    }
                    .into_any(),
                }
            })}
        </Suspense>
    }
}

/// Render the body of one package snapshot: metadata and the versions ×
/// platforms table with narinfo permalinks.
#[component]
fn PackageBody(pkg: PackageSnapshot) -> impl IntoView {
    // Only http(s) homepages become links; any other scheme renders as text.
    let homepage_link = crate::model::homepage_href(pkg.homepage.as_deref());
    let homepage_text = pkg.homepage.clone();
    view! {
        <h1>{pkg.name.clone()}</h1>
        <p>{pkg.description.clone()}</p>
        <table>
            {match homepage_link {
                Some(url) => view! {
                    <tr><th>"Homepage"</th><td><a href=url.clone()>{url.clone()}</a></td></tr>
                }.into_any(),
                None => homepage_text.map(|url| view! {
                    <tr><th>"Homepage"</th><td>{url}</td></tr>
                }).into_any(),
            }}
            <tr><th>"License"</th><td>{pkg.license.clone()}</td></tr>
            <tr><th>"Maintainer"</th><td>{pkg.maintainer.clone()}</td></tr>
        </table>

        <h2>"Versions"</h2>
        <table>
            <tr>
                <th>"Version"</th><th>"Platform"</th><th>"NAR size"</th>
                <th>"Closure size"</th><th>"Store path"</th>
            </tr>
            {pkg.versions.iter().flat_map(|ver| {
                let version = ver.version.clone();
                ver.platforms.iter().map(move |plat| {
                    view! {
                        <tr>
                            <td>{version.clone()}</td>
                            <td>{plat.platform.clone()}</td>
                            <td class="num">{plat.nar_size}</td>
                            <td class="num">{plat.closure_size}</td>
                            <td><code>{plat.store_path.clone()}</code></td>
                        </tr>
                    }
                }).collect::<Vec<_>>()
            }).collect::<Vec<_>>()}
        </table>
    }
}

/// The lazy in-browser verification badge.
///
/// Hidden behind a button so the basic browse works without it; on click it
/// runs [`verify_channel`] for the `stable` channel against the live
/// surface and renders the verified release or the failure reason. This is
/// the *same* verifier the hub indexer and `apm` run — one parser, three
/// runtimes.
#[component]
fn VerifyBadge() -> impl IntoView {
    let (state, set_state) = signal(BadgeState::Idle);

    let verify = move |_| {
        set_state.set(BadgeState::Running);
        spawn_local(async move {
            let fetch = BrowserFetch;
            let next = match verify_channel(&fetch, "stable").await {
                Ok(BadgeOutcome::Verified(badge)) => BadgeState::Verified {
                    channel: badge.channel.clone(),
                    release: badge.short_release(),
                },
                Ok(BadgeOutcome::Failed { reason }) => BadgeState::Failed { reason },
                Err(err) => BadgeState::Failed {
                    reason: format!("{err:#}"),
                },
            };
            set_state.set(next);
        });
    };

    view! {
        <p class="notice">
            <button type="button" class="verify" on:click=verify>
                "Verify in your browser"
            </button>
            " "
            {move || match state.get() {
                BadgeState::Idle => view! {
                    <span class="dim">
                        "runs real Ed25519 verification client-side, same code as apm"
                    </span>
                }.into_any(),
                BadgeState::Running => view! {
                    <span class="dim">"verifying the stable partition…"</span>
                }.into_any(),
                BadgeState::Verified { channel, release } => view! {
                    <span class="ok">
                        "verified in your browser: " {channel} " → commit " {release} "…"
                    </span>
                }.into_any(),
                BadgeState::Failed { reason } => view! {
                    <span class="bad">"verification failed: " {reason}</span>
                }.into_any(),
            }}
        </p>
    }
}

/// The interactive cache closure-graph view.
///
/// Progressively enhances the no-JS closure table (`/<cache>/-/closure/<hash>`)
/// into an indented dependency tree rooted at `root_hash`. The ordering and
/// cycle-handling are the pure [`build_closure_view`] logic (unit-tested on the
/// native build); this component only paints its [`ClosureView`]. Present nodes
/// link to their object page under `slug`; absent references render muted, and a
/// shared/cyclic node shows once with a repeat marker instead of recursing.
#[component]
pub fn ClosureGraph(
    /// The cache slug, for object-page links.
    slug: String,
    /// The closure root's store-path hash.
    root_hash: String,
    /// The flat closure node list from `BinaryCacheService.CacheClosure`.
    nodes: Vec<ClosureNode>,
    /// Total on-disk size of the present closure (bytes).
    total_size: i64,
) -> impl IntoView {
    let view = build_closure_view(&root_hash, &nodes, total_size);
    let summary = format!(
        "{} present · {} missing · {} total",
        view.present_count, view.missing_count, view.total_label,
    );
    let truncated = view.truncated;
    let rows = view.rows.into_iter().map(|row| {
        // Indent by depth with non-breaking guides; mark repeats and misses.
        let indent = "\u{a0}\u{a0}".repeat(row.depth);
        let slug = slug.clone();
        let name_cell = if row.present && !row.repeat {
            view! {
                <a href=format!("/{}/-/objects/{}", slug, row.store_hash)>
                    <code>{row.store_name.clone()}</code>
                </a>
            }
            .into_any()
        } else {
            view! { <code class="dim">{row.store_name.clone()}</code> }.into_any()
        };
        let marker = if row.repeat {
            view! { <span class="dim">" ↺"</span> }.into_any()
        } else if !row.present {
            view! { <span class="bad">" (missing)"</span> }.into_any()
        } else {
            ().into_any()
        };
        view! {
            <tr>
                <td>{indent}{name_cell}{marker}</td>
                <td class="num">{row.size_label}</td>
            </tr>
        }
    });
    view! {
        <h2>"Closure of " <code>{root_hash.clone()}</code></h2>
        <p class="dim">{summary}</p>
        {truncated.then(|| view! {
            <p class="bad">"Closure too large to display in full; showing the first paths."</p>
        })}
        <table>
            <tr><th>"Path"</th><th>"Size"</th></tr>
            {rows.collect::<Vec<_>>()}
        </table>
    }
}

/// The badge's reactive state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
enum BadgeState {
    /// Nothing run yet.
    Idle,
    /// A verification is in flight.
    Running,
    /// The partition verified.
    Verified {
        /// The verified channel name.
        channel: String,
        /// Short release-tag oid for display.
        release: String,
    },
    /// Verification ran and failed (or a transport error occurred).
    Failed {
        /// The reason to show.
        reason: String,
    },
}

/// Extract `name` strings from a hub `ListPackages` response, tolerating the
/// hub's exact field nesting (`{ "packages": [ { "name": … } ] }`).
fn extract_package_names(value: &serde_json::Value) -> Vec<String> {
    value
        .get("packages")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("name").and_then(|n| n.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The package name when the current document path addresses a `browse`
/// page (`browse/<name>.html` or `browse/<name>`), else `None`.
///
/// Reads `window.location.pathname` so the SPA owns the exact URL the static
/// no-JS page occupies. Outside a browser (native tests) it returns `None`.
fn current_browse_package() -> Option<String> {
    let path = document_path()?;
    let after = path.rsplit("browse/").next()?;
    if after == path {
        return None;
    }
    let name = after.strip_suffix(".html").unwrap_or(after);
    let name = name.trim_matches('/');
    (!name.is_empty()).then(|| name.to_string())
}

/// The current document path, or `None` when not running in a browser.
fn document_path() -> Option<String> {
    let window = web_sys_window()?;
    window.location().pathname().ok()
}

/// Thin wrapper around `web_sys::window()` that stays `None` off-browser.
fn web_sys_window() -> Option<leptos::web_sys::Window> {
    leptos::web_sys::window()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_package_names_reads_hub_shape() {
        let value = serde_json::json!({
            "packages": [ { "name": "curl" }, { "name": "zlib" } ]
        });
        assert_eq!(extract_package_names(&value), vec!["curl", "zlib"]);
    }

    #[test]
    fn extract_package_names_tolerates_missing_field() {
        assert!(extract_package_names(&serde_json::json!({})).is_empty());
    }
}
