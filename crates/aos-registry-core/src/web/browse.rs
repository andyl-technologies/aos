//! The shared no-JS browse handlers and JSON read API.
//!
//! RFC-0004 Phase 5 serves the human browse surface from one code path on both
//! deployment targets. These functions sit one level below the transport: each
//! takes the shared [`RpcService`](crate::service::RpcService), a [`PageChrome`]
//! for the masthead, and the request's path parameters, calls the matching
//! `aos.registry.v1` read method, and returns a [`Rendered`] outcome the
//! transport layer ([`crate::connect`]) turns into an HTTP response. They are
//! free of `axum` extractors so the same functions drive the native hub and the
//! Cloudflare Worker (whose handler futures are `?Send`).
//!
//! # URL grammar
//!
//! Human pages and the JSON read API live under the reserved `/-/` segment so
//! they can never shadow the machine surface that owns the registry root
//! (RFC-0004 "The `/-/` namespace"):
//!
//! ```text
//! /                                hub home — list public registries
//! /{slug}/-/                       registry home (HTML)
//! /{slug}/-/packages               package index (HTML)
//! /{slug}/-/packages/{name}        package detail (HTML)
//! /{slug}/-/channels               channel index (HTML)
//! /{slug}/-/channels/{name}        channel 256-partition grid (HTML)
//! /{slug}/-/releases               releases (HTML)
//! /{slug}/-/api/registry           registry meta + index (JSON)
//! /{slug}/-/api/packages           package list (JSON)
//! /{slug}/-/api/packages/{name}    package detail (JSON)
//! /{slug}/-/api/channels           channel list (JSON)
//! /{slug}/-/api/releases           releases (JSON)
//! ```
//!
//! # Visibility
//!
//! These handlers read **anonymously** (they pass no `Authorization` to the
//! read methods), so only `public` registries resolve; a `private`/`internal`
//! registry — like an unknown slug or a missing object — renders as `404`.
//! Session-cookie private browse stays native-hub-side until the console stage.

use aos_proto_types as pb;

use crate::service::RpcService;
use crate::web::render::{self, PageChrome};

/// The outcome of a browse handler: an HTML page, a JSON document, or a miss.
///
/// The transport layer maps these to responses: [`Rendered::Html`] to a `200`
/// `text/html` with the strict `default-src 'self'` CSP, [`Rendered::Json`] to
/// a `200` `application/json`, and [`Rendered::NotFound`] to a bare `404`.
#[derive(Debug, Clone)]
pub enum Rendered {
    /// A complete HTML document.
    Html(String),
    /// A serialized JSON document.
    Json(String),
    /// The resource does not exist or is not publicly visible.
    NotFound,
}

/// Map any read error to a browse miss, and `None` to a miss.
///
/// Browse is anonymous and public-only, so every read failure — an unknown
/// slug, a non-public registry (`PermissionDenied`/`Unauthenticated`), a
/// malformed token, or an internal error — collapses to a `404` rather than
/// leaking a distinction between "absent" and "exists but private".
fn or_not_found<T>(result: Result<T, crate::service::RpcError>) -> Option<T> {
    result.ok()
}

/// The hub home page: every public registry.
///
/// # Errors
///
/// Never errors at the browse layer; an internal read failure renders as the
/// empty registry list (a `200` with "No public registries").
pub async fn home(svc: &RpcService, chrome: &PageChrome) -> Rendered {
    let registries = or_not_found(
        svc.list_registries(None, pb::ListRegistriesRequest::default())
            .await,
    )
    .map(|r| r.registries)
    .unwrap_or_default();
    Rendered::Html(render::home_page(chrome, &registries))
}

/// Fetch one public registry by slug, or a browse miss.
async fn registry(svc: &RpcService, slug: &str) -> Option<pb::Registry> {
    or_not_found(
        svc.get_registry(
            None,
            pb::GetRegistryRequest {
                slug: slug.to_string(),
            },
        )
        .await,
    )
    .and_then(|r| r.registry)
}

/// The registry home page (HTML).
pub async fn registry_home(svc: &RpcService, chrome: &PageChrome, slug: &str) -> Rendered {
    let Some(registry) = registry(svc, slug).await else {
        return Rendered::NotFound;
    };
    let channels = or_not_found(
        svc.list_channels(
            None,
            pb::ListChannelsRequest {
                slug: slug.to_string(),
                ..Default::default()
            },
        )
        .await,
    )
    .map(|r| r.channels)
    .unwrap_or_default();
    let packages = or_not_found(
        svc.list_packages(
            None,
            pb::ListPackagesRequest {
                slug: slug.to_string(),
                ..Default::default()
            },
        )
        .await,
    )
    .map(|r| r.packages)
    .unwrap_or_default();
    Rendered::Html(render::registry_home(chrome, &registry, &channels, &packages))
}

/// The package index page (HTML).
pub async fn packages(svc: &RpcService, chrome: &PageChrome, slug: &str) -> Rendered {
    let Some(registry) = registry(svc, slug).await else {
        return Rendered::NotFound;
    };
    let packages = or_not_found(
        svc.list_packages(
            None,
            pb::ListPackagesRequest {
                slug: slug.to_string(),
                ..Default::default()
            },
        )
        .await,
    )
    .map(|r| r.packages)
    .unwrap_or_default();
    Rendered::Html(render::package_index(chrome, &registry, &packages))
}

/// One package's detail page (HTML).
pub async fn package(svc: &RpcService, chrome: &PageChrome, slug: &str, name: &str) -> Rendered {
    let Some(registry) = registry(svc, slug).await else {
        return Rendered::NotFound;
    };
    let Some(package) = or_not_found(
        svc.get_package(
            None,
            pb::GetPackageRequest {
                slug: slug.to_string(),
                name: name.to_string(),
            },
        )
        .await,
    )
    .and_then(|r| r.package) else {
        return Rendered::NotFound;
    };
    Rendered::Html(render::package_page(chrome, &registry, &package))
}

/// The channels index page (HTML).
pub async fn channels(svc: &RpcService, chrome: &PageChrome, slug: &str) -> Rendered {
    let Some(registry) = registry(svc, slug).await else {
        return Rendered::NotFound;
    };
    let channels = or_not_found(
        svc.list_channels(
            None,
            pb::ListChannelsRequest {
                slug: slug.to_string(),
                ..Default::default()
            },
        )
        .await,
    )
    .map(|r| r.channels)
    .unwrap_or_default();
    Rendered::Html(render::channels_index(chrome, &registry, &channels))
}

/// One channel's 256-partition grid page (HTML).
pub async fn channel(svc: &RpcService, chrome: &PageChrome, slug: &str, name: &str) -> Rendered {
    let Some(registry) = registry(svc, slug).await else {
        return Rendered::NotFound;
    };
    let Some(channel) = or_not_found(
        svc.get_channel(
            None,
            pb::GetChannelRequest {
                slug: slug.to_string(),
                name: name.to_string(),
            },
        )
        .await,
    )
    .and_then(|r| r.channel) else {
        return Rendered::NotFound;
    };
    Rendered::Html(render::channel_page(chrome, &registry, &channel))
}

/// The releases page (HTML).
pub async fn releases(svc: &RpcService, chrome: &PageChrome, slug: &str) -> Rendered {
    let Some(registry) = registry(svc, slug).await else {
        return Rendered::NotFound;
    };
    let releases = or_not_found(
        svc.list_releases(
            None,
            pb::ListReleasesRequest {
                slug: slug.to_string(),
                ..Default::default()
            },
        )
        .await,
    )
    .map(|r| r.releases)
    .unwrap_or_default();
    Rendered::Html(render::releases_page(chrome, &registry, &releases))
}

/// Serialize a serde value as a JSON [`Rendered`], or a miss on failure.
fn json<T: serde::Serialize>(value: &T) -> Rendered {
    match serde_json::to_string(value) {
        Ok(body) => Rendered::Json(body),
        Err(_) => Rendered::NotFound,
    }
}

/// `GET /{slug}/-/api/registry` — registry metadata + index freshness (JSON).
pub async fn api_registry(svc: &RpcService, slug: &str) -> Rendered {
    match registry(svc, slug).await {
        Some(registry) => json(&serde_json::json!({
            "slug": registry.slug,
            "index_state": registry.index_state,
            "registry": registry,
        })),
        None => Rendered::NotFound,
    }
}

/// `GET /{slug}/-/api/packages` — the package list (JSON).
pub async fn api_packages(svc: &RpcService, slug: &str) -> Rendered {
    if registry(svc, slug).await.is_none() {
        return Rendered::NotFound;
    }
    match or_not_found(
        svc.list_packages(
            None,
            pb::ListPackagesRequest {
                slug: slug.to_string(),
                ..Default::default()
            },
        )
        .await,
    ) {
        Some(resp) => json(&resp.packages),
        None => Rendered::NotFound,
    }
}

/// `GET /{slug}/-/api/packages/{name}` — one package's detail (JSON).
pub async fn api_package(svc: &RpcService, slug: &str, name: &str) -> Rendered {
    if registry(svc, slug).await.is_none() {
        return Rendered::NotFound;
    }
    match or_not_found(
        svc.get_package(
            None,
            pb::GetPackageRequest {
                slug: slug.to_string(),
                name: name.to_string(),
            },
        )
        .await,
    )
    .and_then(|r| r.package)
    {
        Some(package) => json(&package),
        None => Rendered::NotFound,
    }
}

/// `GET /{slug}/-/api/channels` — the channel list (JSON).
pub async fn api_channels(svc: &RpcService, slug: &str) -> Rendered {
    if registry(svc, slug).await.is_none() {
        return Rendered::NotFound;
    }
    match or_not_found(
        svc.list_channels(
            None,
            pb::ListChannelsRequest {
                slug: slug.to_string(),
                ..Default::default()
            },
        )
        .await,
    ) {
        Some(resp) => json(&resp.channels),
        None => Rendered::NotFound,
    }
}

/// `GET /{slug}/-/api/releases` — the release list (JSON).
pub async fn api_releases(svc: &RpcService, slug: &str) -> Rendered {
    if registry(svc, slug).await.is_none() {
        return Rendered::NotFound;
    }
    match or_not_found(
        svc.list_releases(
            None,
            pb::ListReleasesRequest {
                slug: slug.to_string(),
                ..Default::default()
            },
        )
        .await,
    ) {
        Some(resp) => json(&resp.releases),
        None => Rendered::NotFound,
    }
}
