//! The Worker `fetch` request dispatch (wasm32-only).
//!
//! Routes one request to the read path. The URL grammar mirrors the native
//! hub (RFC-0004 "URL design — one URL, three audiences"):
//!
//! ```text
//! /                                hub home — list public registries
//! /{slug}/-/                       registry home (HTML)
//! /{slug}/-/packages               package index (HTML)
//! /{slug}/-/packages/{name}        package detail (HTML)
//! /{slug}/-/channels/{name}        channel 256-partition grid (HTML)
//! /{slug}/-/releases               releases (HTML)
//! /{slug}/-/api/registry           registry meta + index (JSON)
//! /{slug}/-/api/packages           package list (JSON)
//! /{slug}/-/api/packages/{name}    package detail (JSON)
//! /{slug}/-/api/channels           channel list (JSON)
//! /{slug}/-/api/releases           releases (JSON)
//! /{slug}/{machine-path}           the R2 facade (HEAD, info/refs, …)
//! /_init                           apply the D1 schema (one-shot, optional)
//! ```
//!
//! Human pages live under the reserved `/-/` segment so they cannot shadow the
//! machine surface that owns the registry root (the GitLab convention; RFC-0004
//! "The `/-/` namespace"). The JSON read API is a **simple JSON shape** under
//! `/-/api/` — the same data the `aos.registry.v1` read services expose, but as
//! plain `application/json` rather than full Connect framing (which is
//! native-only; see the crate README). Only `public` registries resolve: the
//! D1 lookups filter on `visibility = 'public'`, so private/internal registries
//! 404 here without the native-only auth path.

use worker::{Env, Request, Response, Result};

use crate::model::Registry;
use crate::reads::Reads;
use crate::{facade, render};

/// Binding names the Worker expects in `wrangler.toml`.
const D1_BINDING: &str = "REGISTRY_DB";
const R2_BINDING: &str = "REGISTRY_BUCKET";

/// Dispatch one request to the read path.
///
/// # Errors
///
/// Returns an error only for an internal failure (a binding is missing, or a
/// D1/R2 access fails); request-level "not found" is a `404` response, not an
/// error.
pub async fn handle(req: Request, env: Env) -> Result<Response> {
    let url = req.url()?;
    let path = url.path().trim_start_matches('/').to_string();

    if path.is_empty() {
        return hub_home(&env).await;
    }
    if path == "_init" {
        return init_schema(&env).await;
    }

    // Split "{slug}/{rest}". A bare "{slug}" with no trailing content is the
    // registry root; treat it as the registry home.
    let (slug, rest) = match path.split_once('/') {
        Some((slug, rest)) => (slug, rest),
        None => (path.as_str(), ""),
    };

    let db = Reads::new(env.d1(D1_BINDING)?);
    let Some(registry) = db.registry_by_slug(slug).await? else {
        return Response::error("Not Found", 404);
    };

    // Human pages and the JSON API live under "/-/"; everything else is a
    // machine path served from R2.
    if let Some(human) = rest.strip_prefix("-/") {
        human_or_api(&db, &env, &registry, human).await
    } else if rest.is_empty() {
        // "/{slug}" (no trailing slash) — redirect to the registry home.
        Response::redirect(url.join(&format!("/{slug}/-/"))?)
    } else {
        // A machine path under the registry root: serve from R2.
        let bucket = env.bucket(R2_BINDING)?;
        facade::serve(&bucket, &registry, rest).await
    }
}

/// Route a `/-/` sub-path to a browse page or the JSON API.
async fn human_or_api(db: &Reads, _env: &Env, registry: &Registry, sub: &str) -> Result<Response> {
    if let Some(api) = sub.strip_prefix("api/") {
        return api_route(db, registry, api).await;
    }
    let index = db.registry_index(registry.id).await?;
    match sub {
        "" => {
            let roster = db.list_roster(registry.id).await?;
            let channels = db.list_channels(registry.id).await?;
            let packages = db.list_packages(registry.id).await?;
            html(render::registry_home(
                registry, &index, &roster, &channels, &packages,
            ))
        }
        "packages" => {
            let packages = db.list_packages(registry.id).await?;
            let body = render::package_table(&registry.slug, &packages);
            html(render::page(
                &format!("packages — {}", registry.slug),
                &[
                    ("/".into(), "registries".into()),
                    (format!("/{}/-/", registry.slug), registry.slug.clone()),
                    (String::new(), "packages".into()),
                ],
                &body,
                &index,
            ))
        }
        "releases" => {
            let releases = db.list_releases(registry.id).await?;
            html(render::releases_page(&registry.slug, &index, &releases))
        }
        other => {
            if let Some(name) = other.strip_prefix("packages/") {
                match db.package_detail(registry.id, name).await? {
                    Some(detail) => html(render::package_page(&registry.slug, &index, &detail)),
                    None => Response::error("Not Found", 404),
                }
            } else if let Some(name) = other.strip_prefix("channels/") {
                match db.channel(registry.id, name).await? {
                    Some(channel) => html(render::channel_page(&registry.slug, &index, &channel)),
                    None => Response::error("Not Found", 404),
                }
            } else {
                Response::error("Not Found", 404)
            }
        }
    }
}

/// Serve the JSON read API for a registry.
async fn api_route(db: &Reads, registry: &Registry, sub: &str) -> Result<Response> {
    match sub {
        "registry" => {
            let index = db.registry_index(registry.id).await?;
            Response::from_json(&serde_json::json!({
                "slug": registry.slug,
                "visibility": registry.visibility,
                "index": index,
            }))
        }
        "packages" => Response::from_json(&db.list_packages(registry.id).await?),
        "channels" => Response::from_json(&db.list_channels(registry.id).await?),
        "releases" => Response::from_json(&db.list_releases(registry.id).await?),
        other => {
            if let Some(name) = other.strip_prefix("packages/") {
                match db.package_detail(registry.id, name).await? {
                    Some(detail) => Response::from_json(&detail),
                    None => Response::error("Not Found", 404),
                }
            } else {
                Response::error("Not Found", 404)
            }
        }
    }
}

/// The hub home page: every public registry.
async fn hub_home(env: &Env) -> Result<Response> {
    let db = Reads::new(env.d1(D1_BINDING)?);
    let registries = db.list_public_registries().await?;
    html(render::home_page(&registries))
}

/// Apply the canonical D1 schema (a one-shot operational convenience).
///
/// Prefer `wrangler d1 migrations apply` in production; this exists so a fresh
/// database can be initialized without the wrangler migrations workflow.
///
/// This runs the **shared** schema: constructing
/// [`aos_registry_core::db::Database`] over the [`D1Backend`](crate::d1backend::D1Backend)
/// applies the exact `MIGRATIONS` the native hub uses (RFC-0004 Phase 5 — the
/// Worker and the native hub share one `Database`), rather than a Worker-local
/// read-only schema subset.
async fn init_schema(env: &Env) -> Result<Response> {
    use aos_registry_core::db::Database;

    let db_handle = env.d1(D1_BINDING)?;
    Database::with_backend(Box::new(crate::d1backend::D1Backend::new(db_handle)))
        .await
        .map_err(|err| worker::Error::RustError(format!("applying D1 migrations: {err:#}")))?;
    Response::ok("schema applied")
}

/// Build an HTML response with the strict first-party CSP (RFC-0004 asset
/// policy: `default-src 'self'`, no third-party origins).
fn html(body: String) -> Result<Response> {
    let mut response = Response::from_html(body)?;
    let headers = response.headers_mut();
    headers.set("content-security-policy", "default-src 'self'")?;
    Ok(response)
}

/// Re-export the binding names so the README/wrangler config and tests agree.
pub mod bindings {
    /// The D1 database binding name (`wrangler.toml` `[[d1_databases]]`).
    pub const D1: &str = super::D1_BINDING;
    /// The R2 bucket binding name (`wrangler.toml` `[[r2_buckets]]`).
    pub const R2: &str = super::R2_BINDING;
    /// The KV namespace binding name for sessions (`[[kv_namespaces]]`).
    pub const KV_SESSIONS: &str = "SESSIONS";
}
