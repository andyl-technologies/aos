//! The shared, session-aware no-JS browse handlers and JSON read API.
//!
//! RFC-0004 Phase 5 (console-dedup stage G) serves the human browse surface from
//! one code path on both deployment targets, **identically branded, searchable,
//! session-aware, and private-visibility-aware**. These functions sit one level
//! below the transport: each takes the shared
//! [`RpcService`](crate::service::RpcService) and the request's headers/query,
//! resolves the caller's session (so a member sees their org's internal and any
//! granted-private registries while an anonymous visitor sees public only),
//! reads the rich [`db`](crate::db) record types, and returns a [`Rendered`]
//! outcome the transport layer ([`crate::connect`]) turns into an HTTP response.
//! They are free of `axum` extractors (only `axum::http` *types*) so the same
//! functions drive the native hub and the Cloudflare Worker (whose handler
//! futures are `?Send`).
//!
//! # URL grammar
//!
//! Human pages and the JSON read API live under the reserved `/-/` segment so
//! they can never shadow the machine surface that owns the registry root
//! (RFC-0004 "The `/-/` namespace"):
//!
//! ```text
//! /                                hub home — registries (?q= search)
//! /{slug}/-/                       registry home (HTML)
//! /{slug}/-/packages               package index (HTML; ?filter/?sort/?page)
//! /{slug}/-/packages/{name}        package detail (HTML)
//! /{slug}/-/images                 signed system-image downloads (HTML)
//! /{slug}/-/channels               channel index (HTML)
//! /{slug}/-/channels/{name}        channel 256-partition grid (HTML; ?bucket)
//! /{slug}/-/releases               releases (HTML)
//! /{slug}/-/health                 per-registry health (HTML)
//! /{slug}/-/api/registry           registry meta + index (JSON)
//! /{slug}/-/api/packages           package list (JSON)
//! /{slug}/-/api/packages/{name}    package detail (JSON)
//! /{slug}/-/api/channels           channel list (JSON)
//! /{slug}/-/api/releases           releases (JSON)
//! ```
//!
//! # Visibility
//!
//! The HTML pages enforce the RFC-0004 access matrix end to end (the same
//! matrix the producer console's
//! [`authorize_registry_read`](crate::web::console::handlers) applies, reused
//! here over [`RpcService`]'s database and JWT keys): a registry under a
//! soft-deleted org `404`s; `public` (and any unowned registry) is readable by
//! anyone; `internal` requires a session member of the owning org; `private`
//! (and any unknown visibility, fail-closed) requires `Read` at the registry
//! scope from a session *or* a bearer JWT. A hidden registry renders as `404`,
//! never `403`, so its existence is not disclosed. The JSON `/-/api/…` reads are
//! **public-only**: they pass no auth to [`RpcService`] (neither session cookie
//! nor bearer), so only `public` registries resolve and everything else is a
//! `404` — the same shape the Worker served before.

use crate::clock::Instant;

use axum::http::{header, HeaderMap};

use aos_proto_types as pb;

use crate::db::{IndexStatus, RegistryRecord};
use crate::domain::{iam, Permission, Principal, Scope};
use crate::ratelimit::{RateClass, RateDecision};
use crate::service::RpcService;
use crate::web::browse_pages as pages;
use crate::web::console::handlers::resolved_client_ip;
use crate::web::console_render::SessionIndicator;
use crate::web::session;

/// The outcome of a browse handler: an HTML page, a JSON document, a redirect,
/// a rate-limit refusal, or a miss.
///
/// The transport layer ([`crate::connect`]) maps these to responses:
/// [`Rendered::Html`] to a `200` `text/html` with the strict `default-src
/// 'self'` CSP, [`Rendered::Json`] to a `200` `application/json`,
/// [`Rendered::Redirect`] to a `308 Permanent Redirect`,
/// [`Rendered::TooManyRequests`] to a `429` with a `Retry-After`, and
/// [`Rendered::NotFound`] to a bare `404` (which the visibility matrix returns
/// for a hidden or absent registry alike, never disclosing the difference).
#[derive(Debug, Clone)]
pub enum Rendered {
    /// A complete HTML document.
    Html(String),
    /// A serialized JSON document.
    Json(String),
    /// A permanent redirect to the carried location (`/{slug}` → `/{slug}/`).
    Redirect(String),
    /// The per-IP browse budget is exhausted; carries the `Retry-After` seconds.
    TooManyRequests(i64),
    /// The resource does not exist or is not visible to this caller.
    NotFound,
    /// The registry exists and is visible, but a non-HTML client requested it
    /// and the surface ships no machine `index.html` to satisfy the `Accept`
    /// (content negotiation: `406 Not Acceptable`).
    NotAcceptable,
    /// Required topology configuration is absent or temporarily unreadable.
    ServiceUnavailable,
}

/// Maximum packages loaded for one browse page view.
///
/// The browse UI filters, sorts, and paginates in Rust over the whole package
/// `Vec` (the filter is a rich expression that does not push cleanly into SQL),
/// so a registry indexed with an arbitrarily large package set would otherwise
/// let an attacker dictate the per-request memory and CPU cost. The set is
/// capped here with a DB-side `LIMIT`; the page renders a "first N of many"
/// notice when the cap bites. Combined with the per-IP browse rate limit
/// ([`RateClass::BrowseSearch`]) this bounds the work one browse request can
/// force. Sized far above any realistic registry so normal browsing is never
/// truncated.
const MAX_BROWSE_PACKAGES: usize = 10_000;

/// Display cap for the package detail's "required by" reverse-dependency list.
const REVERSE_DEP_CAP: usize = 100;

/// Maximum distinct values embedded per field for the filter autocomplete.
const VALUE_CAP: usize = 500;

/// Maximum repair-job rows shown in the per-registry health page history.
const HEALTH_REPAIR_JOB_LIMIT: i64 = 50;

/// Current Unix time in seconds.
fn now_secs() -> i64 {
    crate::clock::now_unix_secs()
}

/// Map any read error to a browse miss, and `None` to a miss.
fn or_not_found<T>(result: Result<T, crate::service::RpcError>) -> Option<T> {
    result.ok()
}

/// Pull the raw `Authorization` header value, if present and ASCII.
fn auth_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Whether the request's `Accept` header admits an HTML response.
///
/// An absent header is treated as a browser (HTML); a present header must list
/// `text/html`, `text/*`, or `*/*` somewhere.
fn accepts_html(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    accept.split(',').any(|part| {
        let mt = part.split(';').next().unwrap_or("").trim();
        mt.eq_ignore_ascii_case("text/html") || mt.eq_ignore_ascii_case("text/*") || mt == "*/*"
    })
}

/// Resolve the masthead [`SessionIndicator`] for the request.
///
/// Reads the `__Host-aos_session` cookie and resolves the signed-in email, so
/// the page chrome reflects the login state. An anonymous or invalid cookie (or
/// any database error) yields the anonymous indicator.
async fn session_indicator(svc: &RpcService, headers: &HeaderMap) -> SessionIndicator {
    // RFC-0004 ch.14 Phase C: resolve through the KV read-through cache when one
    // is attached (off the relational read path), else straight from the database.
    let resolved = match session::session_secret_from_headers(headers) {
        Some(secret) => svc.resolve_session_cached(&secret).await,
        None => Ok(None),
    };
    match resolved {
        Ok(Some(resolved)) => SessionIndicator::signed_in(resolved.email),
        _ => SessionIndicator::default(),
    }
}

/// Rate-limit a browse/search request, keyed on the deployment-resolved client
/// IP, returning `Some(Rendered::TooManyRequests)` when the budget is spent.
///
/// Reads the ingress-stamped client IP via [`resolved_client_ip`] (see
/// [`CLIENT_IP_HEADER`](crate::web::console::CLIENT_IP_HEADER)) and meters it
/// under [`RateClass::BrowseSearch`]. The expensive anonymous page kinds (the
/// hub home scan and the package index re-load + filter + sort) call this so no
/// entrypoint is an unthrottled hole.
async fn browse_rate_limited(svc: &RpcService, headers: &HeaderMap) -> Option<Rendered> {
    let ip = resolved_client_ip(headers);
    match svc
        .ratelimit
        .check(RateClass::BrowseSearch, &ip, now_secs())
        .await
    {
        RateDecision::Limited { retry_after } => Some(Rendered::TooManyRequests(retry_after)),
        RateDecision::Allowed => None,
    }
}

/// Whether the request's session user may `Read` at `scope` under their current
/// memberships.
async fn session_allows_read(svc: &RpcService, headers: &HeaderMap, scope: &Scope) -> bool {
    let Some(secret) = session::session_secret_from_headers(headers) else {
        return false;
    };
    let Ok(Some(auth)) = svc.db.validate_session(&secret).await else {
        return false;
    };
    let Ok(grants) = svc.db.effective_scopes(Principal::user(auth.user_id)).await else {
        return false;
    };
    let Ok(Some(context)) = svc.db.authorization_context(scope.as_str()).await else {
        return false;
    };
    iam::allow(&grants, Permission::Read, &context)
}

/// Whether the request's session user holds any membership covering `org_id`.
async fn session_is_org_member(svc: &RpcService, headers: &HeaderMap, org_id: i64) -> bool {
    let Some(org) = svc.db.org_by_id(org_id).await.ok().flatten() else {
        return false;
    };
    session_allows_read(svc, headers, &Scope::parse(&org.stable_id)).await
}

/// Whether a bearer JWT in `headers` grants `Read` at `scope`.
async fn bearer_allows_read(svc: &RpcService, headers: &HeaderMap, scope: &Scope) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    match svc.jwt_keys.verify(token) {
        Ok(claims) => svc
            .require_permission(&claims, Permission::Read, scope)
            .await
            .is_ok(),
        Err(_) => false,
    }
}

/// Whether the caller in `headers` may see `registry` at all (the session-aware
/// visibility filter; see the module-level "Visibility" docs for the matrix).
///
/// Reused from the native hub's `can_read_registry`/the producer console's
/// `authorize_registry_read`: a registry under a soft-deleted org is hidden;
/// `public` (and any unowned registry) is visible to anyone; `internal` is
/// visible to a session member of the owning org; `private` (and any unknown
/// visibility, fail-closed) is visible only when a session or bearer token
/// grants `Read` at the registry scope.
async fn can_read_registry(
    svc: &RpcService,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> bool {
    if let Some(org_id) = registry.org_id {
        if !matches!(svc.db.org_is_active(org_id).await, Ok(true)) {
            return false;
        }
    }
    match registry.visibility.as_str() {
        "public" => true,
        "internal" => match registry.org_id {
            None => true,
            Some(org_id) => session_is_org_member(svc, headers, org_id).await,
        },
        _ => {
            let Ok(scope_key) = svc.db.registry_authorization_scope(registry.id).await else {
                return false;
            };
            let scope = Scope::parse(&scope_key);
            session_allows_read(svc, headers, &scope).await
                || bearer_allows_read(svc, headers, &scope).await
        }
    }
}

/// Load a registry by slug, enforcing visibility, plus its index status.
///
/// Returns `None` (rendered as `404`) when the registry does not exist *or* is
/// not visible to this caller — the two are deliberately indistinguishable.
async fn load_visible(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
) -> Option<(RegistryRecord, Option<IndexStatus>)> {
    let registry = svc.db.registry_by_slug(slug).await.ok().flatten()?;
    if !can_read_registry(svc, &registry, headers).await {
        return None;
    }
    let status = svc.db.index_status(registry.id).await.ok().flatten();
    if auth_header(headers).is_none() && session::session_secret_from_headers(headers).is_none() {
        if let Some(kv) = &svc.kv {
            if matches!(crate::directory::read(kv.as_ref()).await, Ok(None)) {
                let _ = crate::directory::rebuild(&svc.db, kv.as_ref()).await;
            }
        }
    }
    Some((registry, status))
}

/// Whether the request's session user may *manage* `registry` (holds
/// `registry.configure` at its canonical scope), so the registry home renders
/// the "manage this registry" link. `false` for anonymous or on any error.
async fn manage_link(svc: &RpcService, registry: &RegistryRecord, headers: &HeaderMap) -> bool {
    let Some(secret) = session::session_secret_from_headers(headers) else {
        return false;
    };
    let Ok(Some(auth)) = svc.db.validate_session(&secret).await else {
        return false;
    };
    let Ok(grants) = svc.db.effective_scopes(Principal::user(auth.user_id)).await else {
        return false;
    };
    let Ok(scope_key) = svc.db.registry_authorization_scope(registry.id).await else {
        return false;
    };
    let Ok(Some(context)) = svc.db.authorization_context(&scope_key).await else {
        return false;
    };
    iam::allow(&grants, Permission::RegistryConfigure, &context)
}

/// Collect strings into a sorted, de-duplicated, length-capped vector, dropping
/// empties — the shape every filter-autocomplete value list takes.
fn distinct_capped(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = values.filter(|v| !v.is_empty()).collect();
    out.sort_unstable();
    out.dedup();
    out.truncate(VALUE_CAP);
    out
}

/// Parsed browse query parameters (`?q`/`?filter`/`?sort`/`?dir`/`?page`).
///
/// `q` is the hub-home substring search; the package index uses `filter` (a
/// [`crate::filter`] expression) with `sort`/`dir` column ordering; `page`
/// paginates every list. Built from the raw URL query string by
/// [`BrowseQuery::parse`] (the transport has no typed extractor in the
/// runtime-neutral handlers).
#[derive(Debug, Default, Clone)]
pub struct BrowseQuery {
    /// Hub-home registries substring search.
    pub q: Option<String>,
    /// Package-index filter expression.
    pub filter: Option<String>,
    /// Package-index sort column token.
    pub sort: Option<String>,
    /// Package-index sort direction token.
    pub dir: Option<String>,
    /// Requested 1-based page.
    pub page: Option<usize>,
    /// Channel-calculator bucket (`?bucket=`).
    pub bucket: Option<String>,
    /// Exact system-image release filter.
    pub release: Option<String>,
    /// Exact system-image channel filter.
    pub channel: Option<String>,
    /// Exact system-image architecture filter.
    pub architecture: Option<String>,
    /// Exact system-image format filter.
    pub format: Option<String>,
    /// Exact system-image target filter.
    pub target: Option<String>,
}

impl BrowseQuery {
    /// Parse the recognized keys from a raw URL query string (`None` when there
    /// is no query); unknown keys are ignored.
    #[must_use]
    pub fn parse(query: Option<&str>) -> Self {
        let mut out = BrowseQuery::default();
        let Some(query) = query else {
            return out;
        };
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "q" => out.q = Some(value.into_owned()),
                "filter" => out.filter = Some(value.into_owned()),
                "sort" => out.sort = Some(value.into_owned()),
                "dir" => out.dir = Some(value.into_owned()),
                "bucket" => out.bucket = Some(value.into_owned()),
                "release" => out.release = Some(value.into_owned()),
                "channel" => out.channel = Some(value.into_owned()),
                "architecture" => out.architecture = Some(value.into_owned()),
                "format" => out.format = Some(value.into_owned()),
                "target" => out.target = Some(value.into_owned()),
                "page" => out.page = value.parse().ok(),
                _ => {}
            }
        }
        out
    }

    /// The trimmed, non-empty hub-home query, if any.
    fn query(&self) -> Option<&str> {
        self.q.as_deref().map(str::trim).filter(|q| !q.is_empty())
    }

    /// The trimmed, non-empty filter expression, if any.
    fn filter(&self) -> Option<&str> {
        self.filter
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
    }

    /// The trimmed, non-empty bucket text, if any.
    fn bucket(&self) -> Option<&str> {
        self.bucket
            .as_deref()
            .map(str::trim)
            .filter(|b| !b.is_empty())
    }

    /// The requested 1-based page, clamped to at least 1.
    fn page_number(&self) -> usize {
        self.page.unwrap_or(1).max(1)
    }
}

/// Maximum number of registries whose visibility + index status the instance
/// home resolves concurrently.
///
/// Bounds the in-flight relational fan-out so a large instance issues a steady wave of
/// statements rather than one giant burst, while still collapsing the page's
/// per-registry N+1 from a serial chain into a handful of round-trip waves.
const HOME_RESOLVE_FANOUT: usize = 16;

/// The hub home page: every registry visible to the caller, with `?q=` search.
///
/// Anonymous and expensive (it scans and visibility-filters every registry), so
/// it is rate-limited per IP. Renders the rich, branded, session-aware instance
/// home; a read failure renders the empty list rather than erroring.
pub async fn home(svc: &RpcService, headers: &HeaderMap, query: &BrowseQuery) -> Rendered {
    if let Some(limited) = browse_rate_limited(svc, headers).await {
        return limited;
    }
    let started = Instant::now();
    let session = session_indicator(svc, headers).await;
    // RFC-0004 ch.14 Phase D: anonymous fast path — serve the public listing
    // from the KV directory projection (one KV read, no per-registry database
    // fan-out — the home N+1) when it has been built. Authenticated requests
    // fall through to the live path, which also resolves private/internal
    // registries the caller may see; a cold projection falls through too.
    if session.email.is_none() {
        if let Some(kv) = &svc.kv {
            let entries = match crate::directory::read(kv.as_ref()).await {
                Ok(Some(entries)) => Some(entries),
                // Bootstrap and data replacement can leave the eventually
                // consistent projection absent. Repair it on the first
                // anonymous request instead of making every request take the
                // relational fallback until the next maintenance tick.
                Ok(None) => crate::directory::rebuild(&svc.db, kv.as_ref()).await.ok(),
                Err(_) => None,
            };
            if let Some(entries) = entries {
                let rows: Vec<(RegistryRecord, Option<IndexStatus>)> = entries
                    .iter()
                    .map(crate::directory::DirectoryEntry::to_row)
                    .collect();
                return Rendered::Html(pages::instance_home(
                    &rows,
                    query.query(),
                    query.page_number(),
                    started,
                    &session,
                ));
            }
        }
    }
    let mut rows: Vec<(RegistryRecord, Option<IndexStatus>)> = Vec::new();
    if let Ok(registries) = svc.db.list_registries().await {
        use futures_util::stream::StreamExt as _;
        // Resolve each registry's visibility and index status concurrently
        // rather than as a serial per-registry chain of database round-trips — the
        // classic N+1 that made the instance home scale its latency with the
        // registry count. `buffered` caps the in-flight fan-out (so a large
        // instance does not issue hundreds of simultaneous statements) and
        // preserves the listing order the page paginates on.
        let resolved: Vec<Option<(RegistryRecord, Option<IndexStatus>)>> =
            futures_util::stream::iter(registries.into_iter().map(|registry| async move {
                // Non-disclosure: only list registries this caller could open.
                if !can_read_registry(svc, &registry, headers).await {
                    return None;
                }
                let status = svc.db.index_status(registry.id).await.ok().flatten();
                Some((registry, status))
            }))
            .buffered(HOME_RESOLVE_FANOUT)
            .collect()
            .await;
        rows.extend(resolved.into_iter().flatten());
    }
    Rendered::Html(pages::instance_home(
        &rows,
        query.query(),
        query.page_number(),
        started,
        &session,
    ))
}

/// The registry home page (HTML), session-aware and content-negotiated.
///
/// A client that does not accept HTML gets the machine surface's `index.html`
/// (the on-CDN web-surface pointer) via the shared facade, or a `404` when none
/// is shipped. Otherwise renders the rich registry home with trust anchors,
/// channels, cache health, the package count, and the setup snippets.
pub async fn registry_home(svc: &RpcService, headers: &HeaderMap, slug: &str) -> Rendered {
    // Content negotiation: non-HTML clients get the machine surface index.html.
    // A registry that is absent or not visible to this caller is a 404; a
    // visible registry that ships no `index.html` is a 406 (the request cannot
    // be satisfied in a non-HTML representation), matching the native hub.
    if !accepts_html(headers) {
        if load_visible(svc, headers, slug).await.is_none() {
            return Rendered::NotFound;
        }
        let auth = auth_header(headers);
        return match svc.surface_fetch(auth.as_deref(), slug, "index.html").await {
            Ok(Some(object)) => Rendered::Json(String::from_utf8_lossy(&object.bytes).into_owned()),
            _ => Rendered::NotAcceptable,
        };
    }
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    // These reads are mutually independent — five keyed only on `registry.id`,
    // plus the session/manage indicators keyed on the request headers — so
    // dispatch them as one concurrent wave rather than a serial chain of database
    // round-trips. On the Worker each underlying query promise is created on first
    // poll and resolves alongside the others, collapsing seven sequential
    // round-trips into one (the dominant cost of this page); on the native
    // sqlx pool they run across pooled connections.
    let ((channels, packages, caches, roster, validations), (session, can_manage)) =
        futures_util::future::join(
            futures_util::future::join5(
                svc.db.list_channels(registry.id),
                svc.db.package_count(registry.id),
                svc.db.registry_cache_stack_entries(registry.id),
                // RFC-0004 ch.14 Phase C: trust roster read-through KV cache.
                svc.list_roster_cached(registry.id),
                svc.db.latest_validation_runs(registry.id),
            ),
            futures_util::future::join(
                session_indicator(svc, headers),
                manage_link(svc, &registry, headers),
            ),
        )
        .await;
    let channels = channels.unwrap_or_default();
    let package_count = packages.unwrap_or_default();
    let caches = resolved_cache_urls(caches.unwrap_or_default());
    let roster = roster.unwrap_or_default();
    let validations = validations.unwrap_or_default();
    let external = svc.registry_consumer_url(&registry).await.ok();
    let setup = pages::RegistrySetup::new(&registry, status.as_ref(), external.as_deref(), &caches);
    Rendered::Html(pages::registry_home(
        &registry,
        status.as_ref(),
        &channels,
        package_count,
        &caches,
        &roster,
        &validations,
        &setup,
        can_manage,
        started,
        &session,
    ))
}

/// The package index page (HTML): apply `?filter`, `?sort`/`?dir`, `?page`.
///
/// Anonymous and expensive (full reload + filter + sort), so it is rate-limited
/// per IP. A malformed filter expression is surfaced inline and the unfiltered
/// list is shown.
pub async fn packages(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    query: &BrowseQuery,
) -> Rendered {
    if let Some(limited) = browse_rate_limited(svc, headers).await {
        return limited;
    }
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let session = session_indicator(svc, headers).await;
    Rendered::Html(
        package_index_html(svc, &registry, status.as_ref(), query, started, &session).await,
    )
}

/// The signed system-image catalog and direct-download page.
pub async fn images(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    query: &BrowseQuery,
) -> Rendered {
    if let Some(limited) = browse_rate_limited(svc, headers).await {
        return limited;
    }
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let (images, channels, session) = futures_util::future::join3(
        svc.db.list_system_images(registry.id),
        svc.db.list_channels(registry.id),
        session_indicator(svc, headers),
    )
    .await;
    let download_base = svc.registry_consumer_url(&registry).await.ok();
    Rendered::Html(pages::images_page(
        &registry,
        status.as_ref(),
        &images.unwrap_or_default(),
        &channels.unwrap_or_default(),
        download_base.as_deref(),
        &pages::ImageBrowse {
            query: query.q.as_deref(),
            release: query.release.as_deref(),
            channel: query.channel.as_deref(),
            architecture: query.architecture.as_deref(),
            format: query.format.as_deref(),
            target: query.target.as_deref(),
        },
        started,
        &session,
    ))
}

/// Render the package index for one registry from the parsed query.
async fn package_index_html(
    svc: &RpcService,
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    query: &BrowseQuery,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    use crate::db::PackageRow;
    use crate::filter::{version_key, Filter};

    let (all, truncated) = svc
        .db
        .list_packages_capped(registry.id, MAX_BROWSE_PACKAGES)
        .await
        .unwrap_or_else(|_| (Vec::new(), false));
    let total_all = all.len();
    let filter_text = query.filter();

    let names = distinct_capped(all.iter().map(|p| p.name.clone()));
    let versions = distinct_capped(all.iter().filter_map(|p| p.latest_version.clone()));
    let licenses = distinct_capped(all.iter().map(|p| p.license.clone()));
    let platforms = distinct_capped(all.iter().flat_map(|p| p.platforms.iter().cloned()));

    let (filter, filter_error) = match Filter::parse(filter_text.unwrap_or("")) {
        Ok(filter) => (filter, None),
        Err(err) => (None, Some(err.to_string())),
    };

    let mut filtered: Vec<PackageRow> = all
        .into_iter()
        .filter(|p| filter.as_ref().is_none_or(|f| f.matches(p)))
        .collect();

    let sort = query
        .sort
        .as_deref()
        .and_then(pages::SortColumn::parse)
        .map(|col| (col, pages::SortDir::parse(query.dir.as_deref())));
    if let Some((col, dir)) = sort {
        filtered.sort_by(|a, b| {
            let ordering = match col {
                pages::SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                pages::SortColumn::Version => version_key(a.latest_version.as_deref())
                    .cmp(&version_key(b.latest_version.as_deref())),
                pages::SortColumn::License => {
                    a.license.to_lowercase().cmp(&b.license.to_lowercase())
                }
                pages::SortColumn::Closure => a
                    .closure_size
                    .unwrap_or(0)
                    .cmp(&b.closure_size.unwrap_or(0)),
                pages::SortColumn::Platforms => a.platforms.join(",").cmp(&b.platforms.join(",")),
            }
            .then_with(|| a.name.cmp(&b.name));
            match dir {
                pages::SortDir::Asc => ordering,
                pages::SortDir::Desc => ordering.reverse(),
            }
        });
    }

    let total_matches = filtered.len();
    let page_number = query.page_number();
    let start = (page_number - 1)
        .saturating_mul(pages::PACKAGES_PER_PAGE)
        .min(total_matches);
    let end = start
        .saturating_add(pages::PACKAGES_PER_PAGE)
        .min(total_matches);
    let browse = pages::PackageBrowse {
        filter: filter_text,
        filter_error: filter_error.as_deref(),
        sort,
        page_number,
        total_matches,
        total_all,
        truncated,
        names: &names,
        versions: &versions,
        licenses: &licenses,
        platforms: &platforms,
    };
    pages::package_index(
        registry,
        status,
        &filtered[start..end],
        &browse,
        started,
        session,
    )
}

/// One package's detail page (HTML), with its resolved forward/reverse closure.
pub async fn package(svc: &RpcService, headers: &HeaderMap, slug: &str, name: &str) -> Rendered {
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let Some(detail) = svc
        .db
        .package_detail(registry.id, name)
        .await
        .ok()
        .flatten()
    else {
        return Rendered::NotFound;
    };
    let (closure, session, caches, external) = futures_util::future::join4(
        resolve_package_closure(svc, registry.id, name, &detail),
        session_indicator(svc, headers),
        svc.db.registry_cache_stack_entries(registry.id),
        svc.registry_consumer_url(&registry),
    )
    .await;
    let caches = resolved_cache_urls(caches.unwrap_or_default());
    let setup = pages::RegistrySetup::new(
        &registry,
        status.as_ref(),
        external.ok().as_deref(),
        &caches,
    );
    Rendered::Html(pages::package_page(
        &registry,
        status.as_ref(),
        &detail,
        &closure,
        &setup,
        started,
        &session,
    ))
}

fn resolved_cache_urls(
    entries: Vec<crate::db::RegistryCacheStackEntryRecord>,
) -> Vec<(String, u32)> {
    entries
        .into_iter()
        .filter_map(|entry| {
            u32::try_from(entry.resolved_priority)
                .ok()
                .map(|priority| (entry.committed_url, priority))
        })
        .collect()
}

/// Resolve a package's forward and reverse closure for the detail page.
async fn resolve_package_closure(
    svc: &RpcService,
    registry_id: i64,
    name: &str,
    detail: &crate::db::PackageDetail,
) -> pages::PackageClosure {
    let primary = detail.versions.first().and_then(|v| v.platforms.first());
    let mut closure = pages::PackageClosure::default();
    if let Some(platform) = primary {
        closure.platform = Some(platform.platform.clone());
        if let Ok(resolved) = svc
            .db
            .resolve_reference_names(registry_id, &platform.refs)
            .await
        {
            closure.dependencies = resolved
                .into_iter()
                .map(|(hash, name, version)| pages::ResolvedDependency {
                    hash,
                    name,
                    version,
                })
                .collect();
        }
    }

    let platform = primary.map(|p| p.platform.as_str()).unwrap_or("");
    if let Ok(Some(store_hash)) = svc.db.primary_store_hash(registry_id, name, platform).await {
        if let Ok(mut reverse) = svc.db.reverse_dependencies(registry_id, &store_hash).await {
            closure.reverse_total = reverse.len();
            reverse.truncate(REVERSE_DEP_CAP);
            closure.reverse = reverse;
        }
    }
    closure
}

/// The channels index page (HTML).
pub async fn channels(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    query: &BrowseQuery,
) -> Rendered {
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let channels = svc.db.list_channels(registry.id).await.unwrap_or_default();
    let session = session_indicator(svc, headers).await;
    Rendered::Html(pages::channels_index(
        &registry,
        status.as_ref(),
        &channels,
        query.page_number(),
        started,
        &session,
    ))
}

/// One channel's 256-partition grid page (HTML), with the `?bucket=` calculator.
pub async fn channel(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    name: &str,
    query: &BrowseQuery,
) -> Rendered {
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let channels = svc.db.list_channels(registry.id).await.unwrap_or_default();
    let Some(channel) = channels.into_iter().find(|c| c.name == name) else {
        return Rendered::NotFound;
    };
    let floor = svc.db.channel_floor(registry.id, name).await.ok().flatten();
    let session = session_indicator(svc, headers).await;
    Rendered::Html(pages::channel_page(
        &registry,
        status.as_ref(),
        &channel,
        floor.as_deref(),
        query.bucket(),
        started,
        &session,
    ))
}

/// The releases page (HTML).
pub async fn releases(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    query: &BrowseQuery,
) -> Rendered {
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let releases = svc.db.list_releases(registry.id).await.unwrap_or_default();
    let session = session_indicator(svc, headers).await;
    Rendered::Html(pages::releases_page(
        &registry,
        status.as_ref(),
        &releases,
        query.page_number(),
        started,
        &session,
    ))
}

/// The per-registry health page (HTML): the cache × coverage validation matrix
/// plus missing/corrupt drill-downs, repair history, freshness, and routes.
pub async fn health(svc: &RpcService, headers: &HeaderMap, slug: &str) -> Rendered {
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let mut runs = Vec::new();
    if let Ok(latest) = svc.db.latest_validation_runs(registry.id).await {
        for run in latest {
            let missing = if run.missing > 0 {
                svc.db.validation_missing(run.id).await.unwrap_or_default()
            } else {
                Vec::new()
            };
            let corrupt = if run.missing > 0 {
                svc.db.validation_corrupt(run.id).await.unwrap_or_default()
            } else {
                Vec::new()
            };
            runs.push((run, missing, corrupt));
        }
    }
    let stack = svc
        .db
        .registry_cache_stack(registry.id)
        .await
        .ok()
        .flatten();
    let probes = svc
        .db
        .list_cache_probes(registry.id)
        .await
        .unwrap_or_default();
    let repair_jobs = svc
        .db
        .list_repair_jobs(registry.id, HEALTH_REPAIR_JOB_LIMIT)
        .await
        .unwrap_or_default();
    let route_records = svc
        .db
        .list_routes(crate::db::SurfaceTarget::Registry(registry.id))
        .await
        .unwrap_or_default();
    let mut routes = Vec::new();
    for route in route_records {
        let Some(snapshot) = svc.db.route_snapshot(&route.id).await.ok().flatten() else {
            continue;
        };
        let mut capabilities = Vec::new();
        if snapshot.spec.serves_git {
            capabilities.push("git".to_string());
        }
        if snapshot.spec.serves_cache {
            capabilities.push("cache".to_string());
        }
        if snapshot.spec.serves_web {
            capabilities.push("web".to_string());
        }
        routes.push(pages::RouteHealthRow {
            id: route.id,
            endpoint_id: route.endpoint_id,
            base_path: route.base_path,
            mode: route.mode,
            enabled: route.enabled,
            capabilities,
        });
    }
    let session = session_indicator(svc, headers).await;
    Rendered::Html(pages::health_page(
        &registry,
        status.as_ref(),
        &runs,
        stack.as_ref(),
        &probes,
        &repair_jobs,
        &routes,
        started,
        &session,
    ))
}

// -- JSON read API ------------------------------------------------------------
//
// -- Managed cache browse (RFC-0004 "11-caches") --------------------------

/// Whether `cache` is readable by this caller — visibility-gated exactly like a
/// registry ([`can_read_registry`]), but scoped on the cache's *owning org*
/// (caches are not org-pathed) or root for an instance-level cache.
async fn can_read_cache(
    svc: &RpcService,
    cache: &crate::db::BinaryCache,
    headers: &HeaderMap,
) -> bool {
    if cache.deleted_at.is_some() {
        return false;
    }
    if let Some(org_id) = cache.org_id {
        if !matches!(svc.db.org_is_active(org_id).await, Ok(true)) {
            return false;
        }
    }
    match cache.visibility.as_str() {
        "public" => true,
        "internal" => match cache.org_id {
            None => true,
            Some(org_id) => session_is_org_member(svc, headers, org_id).await,
        },
        _ => {
            let scope = match cache.org_id {
                Some(org_id) => match svc.db.org_by_id(org_id).await.ok().flatten() {
                    Some(org) => Scope::parse(&org.stable_id),
                    None => return false,
                },
                None => Scope::root(),
            };
            session_allows_read(svc, headers, &scope).await
                || bearer_allows_read(svc, headers, &scope).await
        }
    }
}

/// Load a managed cache by slug iff it is visible to this caller.
async fn load_visible_cache(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
) -> Option<crate::db::BinaryCache> {
    let cache = svc.db.binary_cache_by_slug(slug).await.ok().flatten()?;
    if !can_read_cache(svc, &cache, headers).await {
        return None;
    }
    Some(cache)
}

/// `GET /{slug}/` for a managed cache: the cache home (HTML; non-HTML clients
/// get the machine `nix-cache-info`).
pub async fn cache_home(svc: &RpcService, headers: &HeaderMap, slug: &str) -> Rendered {
    if !accepts_html(headers) {
        if load_visible_cache(svc, headers, slug).await.is_none() {
            return Rendered::NotFound;
        }
        let auth = auth_header(headers);
        return match svc
            .surface_fetch(auth.as_deref(), slug, "nix-cache-info")
            .await
        {
            Ok(Some(o)) => Rendered::Json(String::from_utf8_lossy(&o.bytes).into_owned()),
            _ => Rendered::NotAcceptable,
        };
    }
    let started = Instant::now();
    let Some(cache) = load_visible_cache(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let usage = svc.db.cache_usage(cache.id).await.unwrap_or_default();
    let policy = svc
        .db
        .cache_gc_policy_topology(cache.id)
        .await
        .ok()
        .flatten();
    let subscription_count = svc
        .db
        .list_cache_retention_subscriptions_topology(cache.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let root_count = svc
        .db
        .list_manual_retention_roots_topology(cache.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let external = svc.external_url.clone();
    let pubkey = svc
        .db
        .active_signing_key_for_usage(&cache.stable_id, "narinfo")
        .await
        .ok()
        .flatten()
        .and_then(|key| crate::nix_sign::nix_public_key_from_raw(&key.name, &key.public_key).ok());
    let session = session_indicator(svc, headers).await;
    Rendered::Html(pages::cache_home(
        &cache,
        &usage,
        policy.as_ref(),
        subscription_count,
        root_count,
        &external,
        pubkey.as_deref(),
        started,
        &session,
    ))
}

/// `GET /{slug}/-/objects` for a cache: the object list (HTML; `?q=` search).
pub async fn cache_objects(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    query: &BrowseQuery,
) -> Rendered {
    let started = Instant::now();
    let Some(cache) = load_visible_cache(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let objects = match query.q.as_deref().filter(|q| !q.is_empty()) {
        Some(q) => {
            svc.db
                .search_normalized_cache_objects(cache.id, q, 200)
                .await
        }
        None => svc.db.list_normalized_cache_objects(cache.id, 200).await,
    }
    .unwrap_or_default();
    let session = session_indicator(svc, headers).await;
    Rendered::Html(pages::cache_objects(
        &cache,
        &objects,
        query.q.as_deref(),
        started,
        &session,
    ))
}

/// `GET /{slug}/-/objects/{hash}` for a cache: one object's narinfo + refs.
pub async fn cache_object(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    hash: &str,
) -> Rendered {
    let started = Instant::now();
    let Some(cache) = load_visible_cache(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let Some(object) = svc
        .db
        .normalized_cache_object(cache.id, hash)
        .await
        .ok()
        .flatten()
    else {
        return Rendered::NotFound;
    };
    let session = session_indicator(svc, headers).await;
    Rendered::Html(pages::cache_object(&cache, &object, started, &session))
}

/// `GET /{slug}/-/closure/{hash}` for a cache: a store path's transitive
/// closure as a no-JS table (the dependency graph in flat form).
pub async fn cache_closure(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    hash: &str,
) -> Rendered {
    let started = Instant::now();
    let Some(cache) = load_visible_cache(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    // Reuse the shared closure walk (it re-checks read auth harmlessly).
    let auth = auth_header(headers);
    let Ok(resp) = svc
        .cache_closure(
            auth.as_deref(),
            pb::CacheClosureRequest {
                cache_id: slug.to_string(),
                store_hash: hash.to_string(),
            },
        )
        .await
    else {
        return Rendered::NotFound;
    };
    let session = session_indicator(svc, headers).await;
    Rendered::Html(pages::cache_closure(
        &cache,
        hash,
        &resp.nodes,
        i64::try_from(resp.total_size).unwrap_or(i64::MAX),
        started,
        &session,
    ))
}

/// `GET /{slug}/-/api/objects` for a public cache: the object list (JSON).
pub async fn api_cache_objects(svc: &RpcService, slug: &str, query: &BrowseQuery) -> Rendered {
    // Public-only, like the registry `/-/api/…` reads.
    let Some(cache) = svc.db.binary_cache_by_slug(slug).await.ok().flatten() else {
        return Rendered::NotFound;
    };
    if cache.visibility != "public" || cache.deleted_at.is_some() {
        return Rendered::NotFound;
    }
    // A suspended (soft-deleted) org hides even its public caches, matching the
    // HTML pages' `can_read_cache` gate.
    if let Some(org_id) = cache.org_id {
        if !matches!(svc.db.org_is_active(org_id).await, Ok(true)) {
            return Rendered::NotFound;
        }
    }
    let objects = match query.q.as_deref().filter(|q| !q.is_empty()) {
        Some(q) => {
            svc.db
                .search_normalized_cache_objects(cache.id, q, 500)
                .await
        }
        None => svc.db.list_normalized_cache_objects(cache.id, 500).await,
    }
    .unwrap_or_default();
    let objects: Vec<_> = objects
        .iter()
        .map(|o| {
            serde_json::json!({
                "storeHash": o.store_hash,
                "storeName": o.store_name,
                "narUrl": o.nar_url,
                "narSize": o.nar_size,
                "fileSize": o.file_size,
                "compression": o.compression,
                "references": o.references,
            })
        })
        .collect();
    json(&serde_json::json!({ "objects": objects }))
}

// The machine `/-/api/…` reads are public-only: each passes `None` auth to the
// service read methods (no session cookie and no bearer is forwarded), so only
// `public` registries resolve — the same shape the Worker served before.

/// Fetch one registry by slug for the JSON API, or a browse miss.
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
