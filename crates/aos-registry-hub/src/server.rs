//! Router assembly: one URL space for humans and machines.
//!
//! Per RFC-0004's URL design, a registry URL is simultaneously the human
//! browse surface and the machine surface:
//!
//! ```text
//! /                          instance home (?q= searches registries)
//! /_assets/style.css         the single first-party stylesheet
//! /healthz                   liveness + DB reachability
//! /{slug}/                   registry home (HTML; content-negotiates)
//! /{slug}/-/packages[/name]  human pages (reserved /-/ namespace)
//! /{slug}/-/channels[/name]
//! /{slug}/-/releases
//! /{slug}/-/health
//! /{slug}/<machine path>     dumb-HTTP git + nix-cache facade
//! ```
//!
//! Static segments (`-`, `_assets`) outrank the wildcard in axum's router,
//! so the `/-/` namespace structurally cannot be shadowed by machine
//! paths — and `compat::is_machine_path` rejects everything else.
//!
//! Every response — pages, machine bytes, assets, errors — carries the
//! first-party security headers (`Content-Security-Policy:
//! default-src 'self'`, `X-Content-Type-Options: nosniff`) per RFC-0004's
//! asset policy, and the whole router sits behind a panic-catching layer.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;

use crate::compat;
use crate::db::{Database, IndexStatus, PackageRow, RegistryRecord};
use crate::ui::{pages, STYLESHEET};

/// Shared state for all handlers.
pub struct AppState {
    /// The hub database.
    pub db: Arc<Database>,
    /// The externally reachable base URL, used in setup snippets.
    pub external_url: String,
}

/// Optional search/pagination query parameters (`?q=`, `?page=`).
#[derive(Debug, Default, serde::Deserialize)]
struct SearchParams {
    q: Option<String>,
    page: Option<usize>,
}

/// Optional channel-calculator query parameter (`?bucket=`).
#[derive(Debug, Default, serde::Deserialize)]
struct BucketParams {
    bucket: Option<String>,
}

impl SearchParams {
    /// The trimmed, non-empty search query, if any.
    fn query(&self) -> Option<&str> {
        self.q.as_deref().map(str::trim).filter(|q| !q.is_empty())
    }
}

/// Build the complete hub router.
///
/// `aos.registry.v1` ConnectRPC method paths are static two-segment
/// routes (`/aos.registry.v1.RegistryService/ListRegistries`), so axum's
/// static-over-dynamic precedence keeps them from being shadowed by the
/// `/{slug}/{*path}` facade wildcard.
pub fn router(state: Arc<AppState>) -> Router {
    let rpc = Arc::new(crate::rpc::RegistryRpc {
        db: Arc::clone(&state.db),
    });
    let connect_router = connectrpc::Router::new();
    let connect_router = aos_proto::aos::registry::v1::RegistryServiceExt::register(
        Arc::clone(&rpc),
        connect_router,
    );
    let connect_router =
        aos_proto::aos::registry::v1::PackageServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router =
        aos_proto::aos::registry::v1::ChannelServiceExt::register(rpc, connect_router);
    let connect_paths: Vec<String> = connect_router
        .methods()
        .map(|method| format!("/{method}"))
        .collect();
    let connect_service = connect_router.into_axum_service();

    let mut router = Router::new()
        .route("/", get(instance_home))
        .route("/healthz", get(healthz))
        .route("/_assets/style.css", get(stylesheet))
        .route("/_assets/jetbrains-mono-regular.woff2", get(font_regular))
        .route("/_assets/jetbrains-mono-bold.woff2", get(font_bold))
        .route("/_assets/OFL.txt", get(font_license))
        .route("/{slug}", get(registry_redirect))
        .route("/{slug}/", get(registry_home))
        .route("/{slug}/-/packages", get(package_index))
        .route("/{slug}/-/packages/{name}", get(package_page))
        .route("/{slug}/-/channels", get(channels_index))
        .route("/{slug}/-/channels/{name}", get(channel_page))
        .route("/{slug}/-/releases", get(releases_page))
        .route("/{slug}/-/health", get(health_page))
        .route("/{slug}/{*path}", get(machine_path));
    for path in connect_paths {
        router = router.route_service(&path, connect_service.clone());
    }
    router
        .with_state(state)
        // Panics become plain 500s instead of dropped connections; the
        // security-header layer wraps everything (including those 500s).
        .layer(CatchPanicLayer::new())
        .layer(axum::middleware::from_fn(security_headers))
}

/// Stamp the first-party security headers onto every response.
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Map an internal error into a 500 with a terse body.
fn internal(err: anyhow::Error) -> Response {
    tracing::error!(error = %format!("{err:#}"), "request failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

fn load_registry(
    state: &AppState,
    slug: &str,
) -> Result<Option<(RegistryRecord, Option<IndexStatus>)>, anyhow::Error> {
    let Some(registry) = state.db.registry_by_slug(slug)? else {
        return Ok(None);
    };
    let status = state.db.index_status(registry.id)?;
    Ok(Some((registry, status)))
}

async fn healthz(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_registries() {
        Ok(regs) => (StatusCode::OK, format!("ok ({} registries)\n", regs.len())).into_response(),
        Err(err) => internal(err),
    }
}

async fn stylesheet() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        STYLESHEET,
    )
        .into_response()
}

async fn font_regular() -> Response {
    font_response(crate::ui::FONT_REGULAR)
}

async fn font_bold() -> Response {
    font_response(crate::ui::FONT_BOLD)
}

async fn font_license() -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        crate::ui::FONT_LICENSE,
    )
        .into_response()
}

/// Serve an embedded font.
///
/// The font URLs are stable (not content-hashed), so they get a one-day
/// lifetime rather than `immutable` — a hub upgrade that reships the
/// fonts must be able to take effect.
fn font_response(bytes: &'static [u8]) -> Response {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
        .into_response()
}

async fn instance_home(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Response {
    let started = Instant::now();
    let result = (|| {
        let mut rows = Vec::new();
        for registry in state.db.list_registries()? {
            let status = state.db.index_status(registry.id)?;
            rows.push((registry, status));
        }
        Ok::<_, anyhow::Error>(rows)
    })();
    match result {
        Ok(rows) => Html(pages::instance_home(&rows, params.query(), started)).into_response(),
        Err(err) => internal(err),
    }
}

async fn registry_redirect(Path(slug): Path<String>) -> Redirect {
    Redirect::permanent(&format!("/{slug}/"))
}

/// Whether the request's `Accept` header admits an HTML response.
///
/// An absent header is treated as a browser (HTML); a present header must
/// list `text/html`, `text/*`, or `*/*` somewhere.
fn accepts_html(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    accept.split(',').any(|part| {
        let mt = part.split(';').next().unwrap_or("").trim();
        mt.eq_ignore_ascii_case("text/html") || mt.eq_ignore_ascii_case("text/*") || mt == "*/*"
    })
}

async fn registry_home(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    let started = Instant::now();

    // Content negotiation: clients that do not accept HTML get the
    // machine surface's `index.html` (the on-CDN web-surface pointer),
    // or 406 when the source ships none.
    if !accepts_html(&headers) {
        return match state.db.registry_by_slug(&slug) {
            Ok(Some(registry)) => {
                let response = compat::serve_machine_path(&registry, "index.html").await;
                if response.status() == StatusCode::NOT_FOUND {
                    StatusCode::NOT_ACCEPTABLE.into_response()
                } else {
                    response
                }
            }
            Ok(None) => StatusCode::NOT_FOUND.into_response(),
            Err(err) => internal(err),
        };
    }

    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let channels = state.db.list_channels(registry.id)?;
        let packages = state.db.list_packages(registry.id)?;
        let caches = state.db.list_caches(registry.id)?;
        let roster = state.db.list_roster(registry.id)?;
        let validations = state.db.latest_validation_runs(registry.id)?;
        let external = format!("{}/{slug}", state.external_url.trim_end_matches('/'));
        Ok::<_, anyhow::Error>(Some(pages::registry_home(
            &registry,
            status.as_ref(),
            &channels,
            &packages,
            &caches,
            &roster,
            &validations,
            &external,
            started,
        )))
    })();
    respond_page(result)
}

async fn package_index(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(params): Query<SearchParams>,
) -> Response {
    let started = Instant::now();
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let all = state.db.list_packages(registry.id)?;
        let total_all = all.len();
        let query = params.query();
        let filtered: Vec<PackageRow> = match query {
            Some(query) => {
                let needle = query.to_lowercase();
                all.into_iter()
                    .filter(|p| {
                        p.name.to_lowercase().contains(&needle)
                            || p.description.to_lowercase().contains(&needle)
                    })
                    .collect()
            }
            None => all,
        };
        let total_matches = filtered.len();
        let page_number = params.page.unwrap_or(1).max(1);
        let start = (page_number - 1)
            .saturating_mul(pages::PACKAGES_PER_PAGE)
            .min(total_matches);
        let end = start
            .saturating_add(pages::PACKAGES_PER_PAGE)
            .min(total_matches);
        Ok::<_, anyhow::Error>(Some(pages::package_index(
            &registry,
            status.as_ref(),
            &filtered[start..end],
            query,
            page_number,
            total_matches,
            total_all,
            started,
        )))
    })();
    respond_page(result)
}

async fn package_page(
    State(state): State<Arc<AppState>>,
    Path((slug, name)): Path<(String, String)>,
) -> Response {
    let started = Instant::now();
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let Some(detail) = state.db.package_detail(registry.id, &name)? else {
            return Ok(None);
        };
        Ok::<_, anyhow::Error>(Some(pages::package_page(
            &registry,
            status.as_ref(),
            &detail,
            started,
        )))
    })();
    respond_page(result)
}

async fn channels_index(State(state): State<Arc<AppState>>, Path(slug): Path<String>) -> Response {
    let started = Instant::now();
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let channels = state.db.list_channels(registry.id)?;
        Ok::<_, anyhow::Error>(Some(pages::channels_index(
            &registry,
            status.as_ref(),
            &channels,
            started,
        )))
    })();
    respond_page(result)
}

async fn channel_page(
    State(state): State<Arc<AppState>>,
    Path((slug, name)): Path<(String, String)>,
    Query(params): Query<BucketParams>,
) -> Response {
    let started = Instant::now();
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let channels = state.db.list_channels(registry.id)?;
        let Some(channel) = channels.into_iter().find(|c| c.name == name) else {
            return Ok(None);
        };
        let floor = state.db.channel_floor(registry.id, &name)?;
        Ok::<_, anyhow::Error>(Some(pages::channel_page(
            &registry,
            status.as_ref(),
            &channel,
            floor.as_deref(),
            params.bucket.as_deref(),
            started,
        )))
    })();
    respond_page(result)
}

async fn releases_page(State(state): State<Arc<AppState>>, Path(slug): Path<String>) -> Response {
    let started = Instant::now();
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let releases = state.db.list_releases(registry.id)?;
        Ok::<_, anyhow::Error>(Some(pages::releases_page(
            &registry,
            status.as_ref(),
            &releases,
            started,
        )))
    })();
    respond_page(result)
}

async fn health_page(State(state): State<Arc<AppState>>, Path(slug): Path<String>) -> Response {
    let started = Instant::now();
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let mut runs = Vec::new();
        for run in state.db.latest_validation_runs(registry.id)? {
            let missing = if run.missing > 0 {
                state.db.validation_missing(run.id)?
            } else {
                Vec::new()
            };
            runs.push((run, missing));
        }
        Ok::<_, anyhow::Error>(Some(pages::health_page(
            &registry,
            status.as_ref(),
            &runs,
            started,
        )))
    })();
    respond_page(result)
}

async fn machine_path(
    State(state): State<Arc<AppState>>,
    Path((slug, path)): Path<(String, String)>,
) -> Response {
    match state.db.registry_by_slug(&slug) {
        Ok(Some(registry)) => compat::serve_machine_path(&registry, &path).await,
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

fn respond_page(result: Result<Option<String>, anyhow::Error>) -> Response {
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}
