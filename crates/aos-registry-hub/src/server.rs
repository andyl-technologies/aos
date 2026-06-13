//! Router assembly: one URL space for humans and machines.
//!
//! Per RFC-0004's URL design, a registry URL is simultaneously the human
//! browse surface and the machine surface:
//!
//! ```text
//! /                          instance home
//! /_assets/style.css         the single first-party stylesheet
//! /healthz                   liveness + DB reachability
//! /{slug}/                   registry home (HTML)
//! /{slug}/-/packages[/name]  human pages (reserved /-/ namespace)
//! /{slug}/-/channels[/name]
//! /{slug}/-/releases
//! /{slug}/<machine path>     dumb-HTTP git + nix-cache facade
//! ```
//!
//! Static segments (`-`, `_assets`) outrank the wildcard in axum's router,
//! so the `/-/` namespace structurally cannot be shadowed by machine
//! paths — and `compat::is_machine_path` rejects everything else.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;

use crate::compat;
use crate::db::{Database, IndexStatus, RegistryRecord};
use crate::ui::{pages, STYLESHEET};

/// Shared state for all handlers.
pub struct AppState {
    /// The hub database.
    pub db: Arc<Database>,
    /// The externally reachable base URL, used in setup snippets.
    pub external_url: String,
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
        .route("/{slug}", get(registry_redirect))
        .route("/{slug}/", get(registry_home))
        .route("/{slug}/-/packages", get(package_index))
        .route("/{slug}/-/packages/{name}", get(package_page))
        .route("/{slug}/-/channels", get(channels_index))
        .route("/{slug}/-/channels/{name}", get(channel_page))
        .route("/{slug}/-/releases", get(releases_page))
        .route("/{slug}/{*path}", get(machine_path));
    for path in connect_paths {
        router = router.route_service(&path, connect_service.clone());
    }
    router.with_state(state)
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

async fn instance_home(State(state): State<Arc<AppState>>) -> Response {
    let result = (|| {
        let mut rows = Vec::new();
        for registry in state.db.list_registries()? {
            let status = state.db.index_status(registry.id)?;
            rows.push((registry, status));
        }
        Ok::<_, anyhow::Error>(rows)
    })();
    match result {
        Ok(rows) => Html(pages::instance_home(&rows)).into_response(),
        Err(err) => internal(err),
    }
}

async fn registry_redirect(Path(slug): Path<String>) -> Redirect {
    Redirect::permanent(&format!("/{slug}/"))
}

async fn registry_home(State(state): State<Arc<AppState>>, Path(slug): Path<String>) -> Response {
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let channels = state.db.list_channels(registry.id)?;
        let packages = state.db.list_packages(registry.id)?;
        let caches = state.db.list_caches(registry.id)?;
        let roster = state.db.list_roster(registry.id)?;
        let external = format!("{}/{slug}", state.external_url.trim_end_matches('/'));
        Ok::<_, anyhow::Error>(Some(pages::registry_home(
            &registry,
            status.as_ref(),
            &channels,
            &packages,
            &caches,
            &roster,
            &external,
        )))
    })();
    respond_page(result)
}

async fn package_index(State(state): State<Arc<AppState>>, Path(slug): Path<String>) -> Response {
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let packages = state.db.list_packages(registry.id)?;
        Ok::<_, anyhow::Error>(Some(pages::package_index(
            &registry,
            status.as_ref(),
            &packages,
        )))
    })();
    respond_page(result)
}

async fn package_page(
    State(state): State<Arc<AppState>>,
    Path((slug, name)): Path<(String, String)>,
) -> Response {
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
        )))
    })();
    respond_page(result)
}

async fn channels_index(State(state): State<Arc<AppState>>, Path(slug): Path<String>) -> Response {
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let channels = state.db.list_channels(registry.id)?;
        Ok::<_, anyhow::Error>(Some(pages::channels_index(
            &registry,
            status.as_ref(),
            &channels,
        )))
    })();
    respond_page(result)
}

async fn channel_page(
    State(state): State<Arc<AppState>>,
    Path((slug, name)): Path<(String, String)>,
) -> Response {
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let channels = state.db.list_channels(registry.id)?;
        let Some(channel) = channels.into_iter().find(|c| c.name == name) else {
            return Ok(None);
        };
        Ok::<_, anyhow::Error>(Some(pages::channel_page(
            &registry,
            status.as_ref(),
            &channel,
        )))
    })();
    respond_page(result)
}

async fn releases_page(State(state): State<Arc<AppState>>, Path(slug): Path<String>) -> Response {
    let result = (|| {
        let Some((registry, status)) = load_registry(&state, &slug)? else {
            return Ok(None);
        };
        let releases = state.db.list_releases(registry.id)?;
        Ok::<_, anyhow::Error>(Some(pages::releases_page(
            &registry,
            status.as_ref(),
            &releases,
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
