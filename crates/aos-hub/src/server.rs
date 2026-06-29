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
//! default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options:
//! nosniff`, `X-Frame-Options: DENY`) per RFC-0004's asset policy, and the
//! whole router sits behind a panic-catching layer. Producer-controlled
//! machine-surface documents (HTML/JS a `publish`-scoped producer can upload)
//! are served inert instead — a `sandbox` CSP plus `Content-Disposition:
//! attachment` — so same-origin producer bytes cannot run script in the
//! authenticated hub origin (see [`crate::compat::web_surface_csp`]).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;

/// Maximum inbound request-body size for the RPC, console, and browse surfaces
/// (8 MiB).
///
/// ConnectRPC requests, console form posts, and browse reads carry small JSON
/// or form bodies; capping them well below the process's memory budget keeps a
/// hostile or buggy client from streaming an unbounded body into a handler that
/// buffers it. The large surface-upload `PUT` path is exempt — it is scoped to
/// its own, far larger [`crate::facade::MAX_UPLOAD_BYTES`] limit so legitimate
/// release packs still upload.
pub const RPC_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

use crate::auth::extract::AuthState;
use crate::compat;
use crate::db::{Database, IndexStatus, PackageRow, RegistryRecord};
use crate::domain::{Permission, Principal, Scope};
use crate::ui::pages;

/// Lifetime, in seconds, of a hub access token minted at `/oauth2/token`
/// (1 hour).
///
/// Kept in parity with the Worker
/// (`aos_hub_core::connect`'s `ACCESS_TOKEN_TTL_SECS`): an hour covers a bulk
/// publish while keeping the bearer short-lived; longer-running clients
/// re-exchange the provisioning token rather than relying on a long TTL.
const ACCESS_TOKEN_TTL_SECS: i64 = 3600;

/// Maximum repair-job rows shown in the per-registry health-page history.
const HEALTH_REPAIR_JOB_LIMIT: i64 = 50;

/// Shared state for all handlers.
pub struct AppState {
    /// The hub database.
    pub db: Arc<Database>,
    /// The externally reachable base URL, used in setup snippets.
    pub external_url: String,
    /// Authentication state: JWT keys and the access-token TTL, shared with
    /// the `/oauth2/token` exchange and the mutating ConnectRPC services.
    pub auth: Arc<AuthState>,
    /// Per-registry publish leases held by the upload facade
    /// ([`crate::facade`]); process-local for phase 1/2.
    ///
    /// Shared (as the [`PublishLease`](aos_hub_core::lease::PublishLease)
    /// port) with the shared write handler the facade `PUT`/`HEAD` shims delegate
    /// to, so pointer-flip serialization is process-wide.
    pub leases: Arc<crate::facade::LeaseMap>,
    /// The mailer that delivers magic-link login emails.
    ///
    /// Defaults to [`crate::auth::magic::LogMailer`] (logs the link rather
    /// than sending it) for dev and tests.
    pub mailer: Arc<dyn crate::auth::magic::Mailer>,
    /// Dev mode: when set, the "check your email" page also shows the magic
    /// link inline (since [`LogMailer`] does not send mail). Off in
    /// production.
    ///
    /// [`LogMailer`]: crate::auth::magic::LogMailer
    pub dev: bool,
    /// Sealer for OIDC client secrets at rest (per-org SSO).
    ///
    /// Defaults to the placeholder [`crate::auth::oidc::XorSealer`]; a
    /// production deployment supplies a real AEAD/KMS sealer.
    pub sealer: Arc<dyn crate::auth::oidc::SecretSealer>,
    /// Hardened HTTP client for hub-originated OIDC requests (token exchange,
    /// JWKS fetch), with the same timeouts as the surface fetcher.
    pub http: reqwest::Client,
    /// Process-local rate limiter for the pre-auth endpoints (device
    /// authorization, magic-link issuance, token exchange, browse/search).
    pub ratelimit: Arc<crate::ratelimit::RateLimiter>,
    /// Whether the hub is fronted by a reverse proxy whose `X-Forwarded-For`
    /// header may be trusted to carry the real client IP.
    ///
    /// `false` by default: a directly-exposed hub ignores the (forgeable)
    /// header and rate-limits on the real TCP peer address. Set `true` only
    /// when a proxy that strips inbound `X-Forwarded-For` and appends the true
    /// client hop sits in front. See [`crate::ratelimit`] for the trust model.
    pub trusted_proxy: bool,
}

impl AppState {
    /// Builds an [`AppState`] with ephemeral JWT keys and a [`LogMailer`].
    ///
    /// Convenience for dev mode and tests; production may construct the
    /// struct directly to supply stable keys (so minted access tokens
    /// survive a restart) and a real mailer.
    ///
    /// [`LogMailer`]: crate::auth::magic::LogMailer
    #[must_use]
    pub async fn new(db: Arc<Database>, external_url: String) -> AppState {
        let ratelimit = Arc::new(crate::ratelimit::RateLimiter::new());
        let auth = Arc::new(AuthState {
            db: Arc::clone(&db),
            jwt_keys: crate::auth::jwt::JwtKeys::random(),
            access_token_ttl: ACCESS_TOKEN_TTL_SECS,
            ratelimit: Arc::clone(&ratelimit),
            trusted_proxy: false,
        });
        AppState {
            db,
            external_url,
            auth,
            leases: Arc::new(crate::facade::LeaseMap::new()),
            mailer: Arc::new(crate::auth::magic::LogMailer),
            dev: false,
            // A deterministic placeholder sealer for dev/tests; production
            // supplies a real one via the struct literal.
            sealer: crate::auth::oidc::dev_sealer(),
            http: crate::fetch::hardened_client().await,
            ratelimit,
            trusted_proxy: false,
        }
    }
}

/// A [`RepairAuthorizer`](crate::validation::RepairAuthorizer) for the hub's
/// own managed registry facade URLs.
///
/// An http repair target is hub-writable when its URL is a registry's
/// canonical facade base (`{external_url}/{slug}`). For such a target the
/// authorizer mints an internal short-lived bearer JWT granting `publish` on
/// that registry's scope — the same authorization a producer obtains through
/// `MintUploadCredentials`. For any other URL it returns `None`, so
/// [`crate::validation::run_repairs`] leaves it plan-only.
pub struct HubRepairAuthorizer {
    db: Arc<Database>,
    jwt_keys: crate::auth::jwt::JwtKeys,
    external_url: String,
}

impl HubRepairAuthorizer {
    /// Build an authorizer over the hub's database, signing keys, and base URL.
    #[must_use]
    pub fn new(
        db: Arc<Database>,
        jwt_keys: crate::auth::jwt::JwtKeys,
        external_url: String,
    ) -> HubRepairAuthorizer {
        HubRepairAuthorizer {
            db,
            jwt_keys,
            external_url,
        }
    }
}

#[async_trait::async_trait]
impl crate::validation::RepairAuthorizer for HubRepairAuthorizer {
    async fn credential_for(
        &self,
        target_cache_url: &str,
    ) -> anyhow::Result<Option<crate::validation::RepairCredential>> {
        let base = self.external_url.trim_end_matches('/');
        let target = target_cache_url.trim_end_matches('/');
        // The target must be one of this hub's facade base URLs:
        // {external_url}/{slug}.
        let Some(slug) = target.strip_prefix(base).map(|s| s.trim_start_matches('/')) else {
            return Ok(None);
        };
        // The registry must exist and be writable (have a storage binding).
        let Some(registry) = self.db.registry_by_slug(slug).await? else {
            return Ok(None);
        };
        if registry.storage_binding_id.is_none() {
            return Ok(None);
        }
        // Mint an internal bearer JWT granting publish on the registry scope.
        // The facade authorizes on the JWT's own claims, so a synthetic
        // system-owned TokenAuth suffices.
        let auth = crate::db::TokenAuth {
            token_id: "hub-repair".to_string(),
            owner: Principal::service_account(0),
            scope: Scope::parse(&registry.slug),
            permissions: vec![Permission::Publish],
        };
        let jwt = self
            .jwt_keys
            .mint(&auth, aos_hub_core::service::UPLOAD_CREDENTIAL_TTL_SECS)?;
        Ok(Some(crate::validation::RepairCredential {
            upload_url: format!("{base}/{}", registry.slug),
            bearer_jwt: jwt,
        }))
    }
}

/// Optional search/filter/sort/pagination query parameters.
///
/// `q` is the registries-home substring search; the package index uses
/// `filter` (a [`crate::filter`] expression) with `sort`/`dir` column ordering.
/// `page` paginates every paginated list.
#[derive(Debug, Default, serde::Deserialize)]
struct SearchParams {
    q: Option<String>,
    page: Option<usize>,
    /// Package-index filter expression (Wireshark-style display filter).
    filter: Option<String>,
    /// Package-index sort column (`name`/`version`/`license`/`closure`/
    /// `platforms`); an unknown or absent value leaves the default order.
    sort: Option<String>,
    /// Package-index sort direction (`asc`/`desc`); defaults to descending.
    dir: Option<String>,
}

/// Optional channel-calculator query parameter (`?bucket=`).
#[derive(Debug, Default, serde::Deserialize)]
struct BucketParams {
    bucket: Option<String>,
}

impl SearchParams {
    /// The trimmed, non-empty filter expression, if any.
    fn filter(&self) -> Option<&str> {
        self.filter
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
    }

    /// The requested 1-based page, clamped to at least 1.
    fn page_number(&self) -> usize {
        self.page.unwrap_or(1).max(1)
    }

    /// Parse the recognized keys from a raw URL query string.
    ///
    /// Used on the nested-canonical (`org/registry`) path, where the index is
    /// reached through [`render_page`] rather than an axum `Query` extractor,
    /// so the query must be parsed by hand. Unknown keys are ignored.
    fn from_query(query: Option<&str>) -> Self {
        let mut params = SearchParams::default();
        let Some(query) = query else {
            return params;
        };
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "q" => params.q = Some(value.into_owned()),
                "filter" => params.filter = Some(value.into_owned()),
                "sort" => params.sort = Some(value.into_owned()),
                "dir" => params.dir = Some(value.into_owned()),
                "page" => params.page = value.parse().ok(),
                _ => {}
            }
        }
        params
    }
}

/// Build the complete hub router.
///
/// `aos.registry.v1` Connect-JSON method paths are static two-segment routes
/// (`/aos.registry.v1.RegistryService/ListRegistries`), so axum's
/// static-over-dynamic precedence keeps them from being shadowed by the
/// hub's own `/{slug}/{*path}` facade wildcard.
///
/// The RPC surface is the shared, transport-free
/// [`RpcService`](aos_hub_core::service::RpcService) served as Connect-JSON
/// by [`aos_hub_core::connect::rpc_router`] — the *same* method bodies the
/// Cloudflare Worker mounts (via [`aos_hub_core::connect::router`]) — so the
/// native hub and the Worker speak one wire protocol. The hub mounts the
/// *facade-less* [`rpc_router`](aos_hub_core::connect::rpc_router) and keeps
/// its own richer `/{slug}/{*path}` handler ([`machine_path`] etc.), which the
/// shared facade does not cover: filesystem autoindex and `http(s)` redirect
/// ([`compat::serve_machine_path`]), pull-through mirroring, inert
/// producer-document serving, the upload `PUT`/`HEAD`, and session-cookie
/// authorization. The hub's in-process limiter and surface transports satisfy
/// the service's ports via [`crate::coreports`].
pub async fn router(state: Arc<AppState>) -> Router {
    // The shared Connect-JSON RPC service, built over the hub's database, signing
    // keys, and base URL (the same fields the old per-hub service held), with the
    // in-process limiter adapted to the core `RateLimiter` port and the native
    // surface provider (filesystem/HTTP fetchers chosen per a registry's storage
    // binding).
    let rpc_service = Arc::new(
        aos_hub_core::service::RpcService::new(
            Arc::clone(&state.db),
            state.auth.jwt_keys.clone(),
            state.external_url.clone(),
            Arc::clone(&state.ratelimit) as Arc<dyn aos_hub_core::ratelimit::RateLimiter>,
            Arc::new(
                crate::coreports::HubSurfaceProvider::new(Arc::clone(&state.db))
                    .with_sealer(Arc::clone(&state.sealer)),
            ),
            Arc::new(
                crate::coreports::HubSurfaceWriteProvider::new(Arc::clone(&state.db))
                    .with_sealer(Arc::clone(&state.sealer)),
            ),
            // The shared service's publish lease is the *same* in-memory lease the
            // hub's own facade `PUT`/`HEAD` shims hold ([`AppState::leases`]), so
            // pointer-flip serialization is process-wide whether a write arrives via
            // the hub's `/{slug}/{*path}` route or (in principle) the shared facade
            // route.
            Arc::clone(&state.leases) as Arc<dyn aos_hub_core::lease::PublishLease>,
            Arc::new(crate::coreports::HubReindexer::new(Arc::clone(&state.db))),
            Some(Arc::clone(&state.sealer)),
        )
        .with_origin_fetch(Arc::new(crate::coreports::ReqwestOriginFetch::new(
            state.http.clone(),
        ))),
    );
    // The shared router owns `/aos.registry.v1.*` and carries its own axum state
    // (the `Arc<RpcService>`), so it is already fully stated; it is merged into
    // the finished AppState-stated router below. The *facade-less* variant is
    // used: the hub keeps its own `/{slug}/{*path}` machine-surface handler
    // (autoindex/http-redirect/pull-through/producer-document/session auth), so
    // merging the shared facade's identical wildcard would panic on the overlap.
    // A small inbound body cap is scoped to *just* the RPC surface (the large
    // surface-upload PUT path keeps its own, far larger limit).
    // `RequestBodyLimitLayer` enforces the cap at the body-stream level (`413
    // Payload Too Large`) regardless of how the handler consumes the body.
    // Kept for the outermost domain-routing layer below (it captures the service
    // directly, independent of the AppState-typed router's state).
    let dispatch_service = Arc::clone(&rpc_service);
    let rpc_router = aos_hub_core::connect::rpc_browse_router(rpc_service).layer(
        tower_http::limit::RequestBodyLimitLayer::new(RPC_MAX_BODY_BYTES),
    );

    // The `/oauth2/token` exchange fragment runs on Arc<AuthState>; bind its
    // state up front so it merges into the AppState-typed router below.
    let oauth2 = crate::auth::extract::oauth2_router().with_state(Arc::clone(&state.auth));

    // The flat browse routes (the hub home `/`, the `/{slug}` redirect, the
    // registry home `/{slug}/`, and the `/{slug}/-/…` human pages + JSON read
    // API) are no longer registered here: RFC-0004 Phase 5 console-dedup stage
    // G mounts the *shared* session-aware browse via
    // `aos_hub_core::connect::rpc_browse_router` (merged below), so the
    // native hub and the Worker serve the identical browse. The hub keeps only
    // its serving endpoints (`/healthz`, `/metrics`, the device-authorization
    // POST) and its own richer machine-surface facade (`/{slug}/{*path}` and the
    // nested-canonical catch-all). The `/_assets/*` static files are served by
    // the shared browse router (merged below) so both shells expose them.
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route(
            "/oauth2/device_authorization",
            axum::routing::post(device_authorization),
        )
        .route(
            "/{slug}/{*path}",
            get(machine_path)
                .post(post_machine_path)
                .put(put_machine_path)
                .head(head_machine_path)
                // The surface-upload PUT/POST legitimately carries large release
                // packs, so this route opts out of the small global RPC body cap
                // and uses the facade's own large limit. Applied as a per-route
                // layer, it overrides the router-wide `DefaultBodyLimit` below
                // (per-route layers run inside the router layer, so the
                // innermost limit the body extractor sees wins).
                .layer(DefaultBodyLimit::max(crate::facade::MAX_UPLOAD_BYTES)),
        );
    // The nested-canonical catch-all is registered last: axum's
    // static-over-dynamic precedence keeps the explicit routes above
    // (healthz, _assets, oauth2, RPC method paths, the flat `/{slug}` shapes)
    // winning, and only requests matching none of them reach the resolver.
    // The fallback handles every method so nested-canonical registries
    // (slugs with slashes) accept the upload facade's PUT/HEAD too.
    router = router.fallback(nested_catch_all);
    // The shared producer-console router (RFC-0004 Phase 5, console-dedup stage
    // B): the wasm-clean management handlers, built over the hub's database,
    // JWT keys, rate limiter, mailer, sealer, the hardened reqwest `HttpClient`
    // port, and the native surface read/write and reindex ports (over which the
    // shared `signing::advance_channel` runs a hosted-key channel advance).
    // It carries its own `ConsoleDeps` state, so — like `rpc_router` — it is
    // merged after `with_state` below. Nested-canonical registry console pages
    // (slugs with slashes, which the flat `/{slug}/-/…` routes can't capture)
    // are served by the same shared dispatcher from the catch-all — see
    // [`console_deps`] and `dispatch_nested` — so there is a single console
    // routing table for both flat and nested slugs.
    let mut console_deps = console_deps(&state);
    // The native hub's default store is its DB-recorded storage root; surface it
    // so instance settings shows where unbound surfaces live (falls back to
    // "configured at deploy time" when unset). Only the flat console router (which
    // serves the instance-settings page) needs it, so it is set here rather than
    // in the shared `console_deps` builder used by the nested dispatcher.
    console_deps.default_storage_location = state.db.default_storage_root().await.ok().flatten();
    // Seed the editable site chrome (title/banner/footer) from D1 at startup so
    // the masthead reflects persisted branding; a branding save refreshes it
    // live via `set_site_chrome`.
    if let Ok(s) = state.db.instance_settings().await {
        aos_hub_core::web::console_render::set_site_chrome(
            s.site_title.as_deref(),
            s.tagline.as_deref(),
            s.announcement.as_deref(),
            s.tos_url.as_deref(),
            s.privacy_url.as_deref(),
            s.support_url.as_deref(),
        );
        aos_hub_core::web::console_render::set_caches_public(s.caches_public);
    }
    let console_router = aos_hub_core::web::console::console_router(console_deps);
    // Kept for the outermost client-IP injection layer below, which runs after
    // `with_state` moves `state` into the router.
    let ip_state = Arc::clone(&state);
    let app = router
        .merge(oauth2)
        // Resolve the request's session once and put the user's email in a
        // task-local, so every page's masthead reflects the login + shows
        // navigation without threading the identity through each handler.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            resolve_session,
        ))
        .with_state(state)
        // The shared Connect-JSON RPC router carries its own `Arc<RpcService>`
        // state, so it is merged after `with_state` (when the surrounding router
        // is `Router<()>` too). Its static `/aos.registry.v1.*` paths win over
        // the hub's own `/{slug}/{*path}` facade wildcard by static-over-dynamic
        // precedence. It is the facade-less variant (`rpc_router`), so it does
        // not redefine `/{slug}/{*path}` and cannot collide with the hub's
        // handler on merge. The outer layers below (body cap, panic catcher,
        // security headers) still wrap its responses.
        .merge(rpc_router)
        // The shared producer-console router carries its own `ConsoleDeps`
        // state, so — like `rpc_router` — it is merged after `with_state`. Its
        // static console paths (/account, /-/org…, /{slug}/-/settings…) win over
        // the hub's `/{slug}/{*path}` facade wildcard by static-over-dynamic
        // precedence. The outer layers below (body cap, panic catcher, security
        // headers) wrap its responses too, so a console handler that sets its own
        // CSP (the passkey pages) is still honored.
        .merge(console_router)
        // Router-wide inbound body cap. The RPC surface is already bounded to
        // the smaller `RPC_MAX_BODY_BYTES` by its own sub-router layer above
        // (which, being closer to the handler, wins for those routes). This
        // outer default bounds every *other* route — including the
        // nested-canonical upload fallback — at the surface-upload limit, so a
        // large release pack still uploads while no route is left with an
        // unbounded inbound body. The flat upload route additionally pins this
        // same large limit explicitly so its bound is independent of layer
        // ordering.
        .layer(DefaultBodyLimit::max(crate::facade::MAX_UPLOAD_BYTES))
        // Panics become plain 500s instead of dropped connections; the
        // security-header layer wraps everything (including those 500s).
        .layer(CatchPanicLayer::new())
        .layer(axum::middleware::from_fn(security_headers))
        // The OUTERMOST layer: it runs first on the way in, so it stamps the
        // shell-resolved client IP onto the `x-aos-client-ip` header (overwriting
        // any inbound value) before any merged router — including the shared
        // console's pre-auth login routes — sees the request. See
        // [`inject_client_ip`] for the forge-resistance invariant.
        .layer(axum::middleware::from_fn_with_state(
            ip_state,
            inject_client_ip,
        ));
    // Domain-routed frontends (RFC-0004): a request on a per-registry/per-cache
    // proxied domain is rewritten to its bound `/{slug}/…` identity by `Host`
    // before any route matches. Outermost so it runs first on the way in.
    aos_hub_core::connect::with_frontend_dispatch(app, dispatch_service)
}

/// Resolve the current session and run the request with the user's email in
/// a task-local (read by the page renderer's masthead).
async fn resolve_session(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let email = match session_secret_from_cookies(request.headers()) {
        Some(secret) => state.db.session_email(&secret).await.ok().flatten(),
        None => None,
    };
    crate::ui::render::with_session_email(email, next.run(request)).await
}

/// Stamp the first-party security headers onto every response.
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // Default policy is `default-src 'self'; frame-ancestors 'none'` (no inline
    // scripts, and the response may not be framed — anti-clickjacking for the
    // console and the device-approval `/activate` page). The passkey pages are
    // the one no-JS exception (WebAuthn requires `navigator.credentials`): they
    // set their own per-request CSP carrying a nonce in `script-src` before
    // this layer runs, so honor a handler-set CSP rather than clobbering it.
    // Producer machine-surface documents likewise set their own `sandbox` CSP
    // (which already forbids framing). Every other response gets the strict
    // default. `frame-ancestors` is the modern control; `X-Frame-Options:
    // DENY` is set unconditionally below as the legacy belt-and-braces, so even
    // a handler that supplies its own CSP without `frame-ancestors` stays
    // unframeable.
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert_with(|| HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// Map an internal error into a 500 with a terse body.
pub(crate) fn internal(err: anyhow::Error) -> Response {
    tracing::error!(error = %format!("{err:#}"), "request failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// Current Unix time in seconds.
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Rate-limit an anonymous browse/search request, keyed on the client IP.
///
/// Resolves the client IP exactly as the auth handlers do
/// ([`client_ip_for`]) and meters it under
/// [`RateClass::BrowseSearch`](crate::ratelimit::RateClass::BrowseSearch).
/// Returns `Some(429)` (with `Retry-After`) when the loose per-IP browse
/// budget is exhausted, and `None` when the request may proceed. Both the flat
/// `/{slug}/-/packages` route and the nested-canonical `org/registry/-/…`
/// resolver call this so neither entrypoint is an unthrottled hole.
pub(crate) fn browse_rate_limited(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<Response> {
    let ip = client_ip_for(headers, peer, state.trusted_proxy);
    match state
        .ratelimit
        .check(crate::ratelimit::RateClass::BrowseSearch, &ip, now_secs())
    {
        crate::ratelimit::RateDecision::Limited { retry_after } => {
            Some(too_many_requests(retry_after))
        }
        crate::ratelimit::RateDecision::Allowed => None,
    }
}

/// A `429 Too Many Requests` response carrying a `Retry-After` header.
pub(crate) fn too_many_requests(retry_after: i64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.max(1).to_string())],
        "rate limit exceeded",
    )
        .into_response()
}

/// The connecting client's TCP peer address, when the serving stack provides
/// it via [`ConnectInfo`].
///
/// An infallible [`FromRequestParts`](axum::extract::FromRequestParts)
/// extractor: it reads the [`ConnectInfo<SocketAddr>`] extension injected by
/// `into_make_service_with_connect_info` in production, and is simply `None`
/// when no connect-info is present (e.g. `Router::oneshot` in tests). Used as
/// the safe rate-limit key when the deployment does not trust a proxy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerAddr(pub Option<SocketAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(PeerAddr(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0),
        ))
    }
}

/// Resolve the request's client IP for rate-limiting from the TCP `peer`
/// address and, only when the deployment trusts its proxy, `X-Forwarded-For`.
///
/// `peer` is the real connecting address (from the `ConnectInfo` extractor);
/// it is the limiter key whenever `trusted_proxy` is `false`, so a forged
/// `X-Forwarded-For` cannot mint a fresh per-IP bucket. When `trusted_proxy`
/// is `true` the last forwarded hop is honored instead. See [`crate::ratelimit`]
/// for the trust model.
pub(crate) fn client_ip_for(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_proxy: bool,
) -> String {
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let peer = peer.map(|p| p.ip().to_string()).unwrap_or_default();
    crate::ratelimit::client_ip(xff, &peer, trusted_proxy)
}

/// Stamp the trusted client IP onto the runtime-neutral
/// [`CLIENT_IP_HEADER`](aos_hub_core::web::console::CLIENT_IP_HEADER) so the
/// shared console's pre-auth login handlers meter on it.
///
/// The shared `/login` and `/login/password` handlers (RFC-0004 Phase 5,
/// console-dedup stage D) are wasm-clean and cannot read the native
/// [`ConnectInfo`] peer socket or the per-deployment reverse-proxy trust flag, so
/// they read the connecting IP from a header instead. This middleware resolves
/// the *trusted* IP with the hub's existing [`client_ip_for`] (the same
/// resolution every other auth path uses — peer socket by default, last
/// forwarded hop only when `trusted_proxy`) and **overwrites** the header with
/// it, replacing any inbound value of the same name.
///
/// # Security invariant
///
/// The overwrite (`insert`, not `append`) is load-bearing: a client could
/// otherwise supply its own `x-aos-client-ip` and forge a fresh per-IP
/// rate-limit bucket on the unauthenticated login paths. Because this is applied
/// as the **outermost** router layer (after every `.merge`), it covers the shared
/// console routes too, so a forged inbound value never survives to a handler. The
/// peer may be `None` under a test server with no connect-info; [`client_ip_for`]
/// resolves that to an empty string, which still meters (coarsely) rather than
/// failing open.
async fn inject_client_ip(
    State(state): State<Arc<AppState>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let ip = client_ip_for(request.headers(), peer, state.trusted_proxy);
    if let Ok(value) = HeaderValue::from_str(&ip) {
        request
            .headers_mut()
            .insert(aos_hub_core::web::console::CLIENT_IP_HEADER, value);
    } else {
        // A resolved IP is always header-safe ASCII, but if it somehow is not,
        // remove any inbound value so a client cannot smuggle a forged bucket.
        request
            .headers_mut()
            .remove(aos_hub_core::web::console::CLIENT_IP_HEADER);
    }
    next.run(request).await
}

async fn healthz(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_registries().await {
        Ok(regs) => (StatusCode::OK, format!("ok ({} registries)\n", regs.len())).into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /oauth2/device_authorization` form (RFC 8628).
#[derive(Debug, Default, serde::Deserialize)]
struct DeviceAuthForm {
    /// Requested scope path (defaults to the instance root when omitted).
    scope: Option<String>,
    /// Requested permission verb (repeatable via the form encoding; defaults
    /// to `read`).
    #[serde(default)]
    permission: Vec<String>,
}

/// `POST /oauth2/device_authorization` — start an RFC 8628 device grant.
///
/// Anonymous and **rate-limited per source IP** (the abuse surface the RFC
/// calls out): a flood from one IP is `429`d with `Retry-After`. On success it
/// returns the RFC 8628 JSON (`device_code`, `user_code`,
/// `verification_uri`, `expires_in`, `interval`). The requested scope and
/// permissions are recorded but not authorized here — the approving user's
/// grants clamp them at `/activate`.
async fn device_authorization(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<DeviceAuthForm>,
) -> Response {
    let ip = client_ip_for(&headers, peer, state.trusted_proxy);
    if let crate::ratelimit::RateDecision::Limited { retry_after } = state.ratelimit.check(
        crate::ratelimit::RateClass::DeviceAuthorization,
        &ip,
        now_secs(),
    ) {
        return too_many_requests(retry_after);
    }
    let scope = form.scope.unwrap_or_default();
    let perms: Vec<Permission> = if form.permission.is_empty() {
        vec![Permission::Read]
    } else {
        form.permission
            .iter()
            .filter_map(|p| crate::auth::permission_from_str(p))
            .collect()
    };
    match state.db.start_device_authorization(&scope, &perms).await {
        Ok((device_code, user_code, expires_in)) => {
            let verification_uri = format!("{}/activate", state.external_url.trim_end_matches('/'));
            let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
            axum::Json(serde_json::json!({
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": verification_uri,
                "verification_uri_complete": verification_uri_complete,
                "expires_in": expires_in,
                "interval": 5,
            }))
            .into_response()
        }
        Err(err) => internal(err),
    }
}

/// The Prometheus text-exposition `/metrics` endpoint.
///
/// Hand-formats the [exposition format] (no client dependency, per the
/// hermetic build) from live database counts: total registries and a
/// per-`state` breakdown, the webhook-delivery queue depth by lifecycle,
/// managed-cache totals (caches, objects, bytes) and lifetime GC counters
/// (runs by outcome, bytes reclaimed), and a `build_info` gauge carrying the
/// crate version as a label. Every series is preceded by its `# HELP`/`# TYPE`
/// lines.
///
/// [exposition format]: https://prometheus.io/docs/instrumenting/exposition_formats/
async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let body = match render_metrics(&state).await {
        Ok(body) => body,
        Err(err) => return internal(err),
    };
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// Render the `/metrics` exposition body from current database state.
///
/// # Errors
///
/// Returns an error on database failure.
async fn render_metrics(state: &AppState) -> Result<String, anyhow::Error> {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let registries = state.db.list_registries().await?;
    let mut by_state: BTreeMap<String, u64> = BTreeMap::new();
    for registry in &registries {
        let label = state
            .db
            .index_status(registry.id)
            .await?
            .map(|s| s.state)
            .unwrap_or_else(|| "indexing".to_string());
        *by_state.entry(label).or_default() += 1;
    }
    let (pending, delivered, failed) = state.db.delivery_status_counts().await?;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP aos_hub_registries_total Registered registries.\n\
         # TYPE aos_hub_registries_total gauge\n\
         aos_hub_registries_total {}",
        registries.len()
    );
    let _ = writeln!(
        out,
        "# HELP aos_hub_registries_by_state Registered registries by index state.\n\
         # TYPE aos_hub_registries_by_state gauge"
    );
    // Always emit the four known states (zero when absent) so a scrape never
    // loses a series, then any other state the index reports.
    for known in ["fresh", "indexing", "stale", "failed"] {
        let n = by_state.remove(known).unwrap_or(0);
        let _ = writeln!(out, "aos_hub_registries_by_state{{state=\"{known}\"}} {n}");
    }
    for (extra, n) in &by_state {
        let _ = writeln!(out, "aos_hub_registries_by_state{{state=\"{extra}\"}} {n}");
    }
    let _ = writeln!(
        out,
        "# HELP aos_hub_webhook_deliveries Webhook deliveries by status.\n\
         # TYPE aos_hub_webhook_deliveries gauge\n\
         aos_hub_webhook_deliveries{{status=\"pending\"}} {pending}\n\
         aos_hub_webhook_deliveries{{status=\"delivered\"}} {delivered}\n\
         aos_hub_webhook_deliveries{{status=\"failed\"}} {failed}"
    );
    let cm = state.db.cache_metrics().await?;
    let _ = writeln!(
        out,
        "# HELP aos_hub_caches_total Managed binary caches (live).\n\
         # TYPE aos_hub_caches_total gauge\n\
         aos_hub_caches_total {}\n\
         # HELP aos_hub_cache_objects_total Indexed cache objects across live caches.\n\
         # TYPE aos_hub_cache_objects_total gauge\n\
         aos_hub_cache_objects_total {}\n\
         # HELP aos_hub_cache_bytes_total Stored cache bytes across live caches.\n\
         # TYPE aos_hub_cache_bytes_total gauge\n\
         aos_hub_cache_bytes_total {}",
        cm.cache_count, cm.object_count, cm.used_bytes
    );
    let _ = writeln!(
        out,
        "# HELP aos_hub_cache_gc_runs Cache GC runs by outcome (lifetime).\n\
         # TYPE aos_hub_cache_gc_runs counter\n\
         aos_hub_cache_gc_runs{{status=\"ok\"}} {}\n\
         aos_hub_cache_gc_runs{{status=\"failed\"}} {}\n\
         # HELP aos_hub_cache_gc_freed_bytes Bytes reclaimed by cache GC (lifetime).\n\
         # TYPE aos_hub_cache_gc_freed_bytes counter\n\
         aos_hub_cache_gc_freed_bytes {}",
        cm.gc_runs_ok, cm.gc_runs_failed, cm.gc_freed_bytes
    );
    let _ = writeln!(
        out,
        "# HELP aos_hub_build_info Build information.\n\
         # TYPE aos_hub_build_info gauge\n\
         aos_hub_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    Ok(out)
}

/// Maximum packages loaded for one anonymous browse page view.
///
/// The browse UI filters, sorts, and paginates in Rust over the whole package
/// `Vec` (the filter is a rich expression that does not push cleanly into
/// SQL), so a registry indexed with an arbitrarily large package set would
/// otherwise let an attacker dictate the per-request memory and CPU cost. The
/// set is capped here with a DB-side `LIMIT`; the page renders a "first N of
/// many" notice when the cap bites. Combined with the per-IP browse rate limit
/// ([`RateClass::BrowseSearch`](crate::ratelimit::RateClass::BrowseSearch)) and
/// the indexer's package cap
/// ([`MAX_PACKAGES`](crate::surface::load::MAX_PACKAGES)), this bounds the work
/// a single browse request can force. Sized far above any realistic registry so
/// normal browsing is never truncated.
const MAX_BROWSE_PACKAGES: usize = 10_000;

/// Render the package index for one registry: apply the `?filter=` expression,
/// the `?sort=`/`?dir=` column order, and the `?page=` slice, then build the
/// page.
///
/// Shared by the flat [`package_index`] route and the nested-canonical
/// [`render_page`] path so both honor the query string identically — the
/// org-scoped (`org/registry`) URLs reach the index through `render_page`.
///
/// # Errors
///
/// Returns an error if loading the registry's package list fails. A malformed
/// filter expression is *not* an error: the page renders the unfiltered list
/// with the parse error surfaced inline.
async fn package_index_html(
    state: &AppState,
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    params: &SearchParams,
    started: Instant,
) -> Result<String, anyhow::Error> {
    use crate::filter::{version_key, Filter};

    let (all, truncated) = state
        .db
        .list_packages_capped(registry.id, MAX_BROWSE_PACKAGES)
        .await?;
    let total_all = all.len();
    let filter_text = params.filter();

    // The distinct per-field values that drive the filter box's autocomplete,
    // computed from the whole registry (the suggestion set should not shrink as
    // the filter narrows the list) and capped so the data island stays light.
    let names = distinct_capped(all.iter().map(|p| p.name.clone()));
    let versions = distinct_capped(all.iter().filter_map(|p| p.latest_version.clone()));
    let licenses = distinct_capped(all.iter().map(|p| p.license.clone()));
    let platforms = distinct_capped(all.iter().flat_map(|p| p.platforms.iter().cloned()));

    // Parse the filter expression. A parse error keeps the list unfiltered and
    // is surfaced in the page so the user can correct it.
    let (filter, filter_error) = match Filter::parse(filter_text.unwrap_or("")) {
        Ok(filter) => (filter, None),
        Err(err) => (None, Some(err.to_string())),
    };

    let mut filtered: Vec<PackageRow> = all
        .into_iter()
        .filter(|p| filter.as_ref().is_none_or(|f| f.matches(p)))
        .collect();

    // Column sort: only when `?sort=` names a known column. The default order
    // (none) is the DB's name-ascending order.
    let sort = params
        .sort
        .as_deref()
        .and_then(pages::SortColumn::parse)
        .map(|col| (col, pages::SortDir::parse(params.dir.as_deref())));
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
    let page_number = params.page.unwrap_or(1).max(1);
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
    Ok(pages::package_index(
        registry,
        status,
        &filtered[start..end],
        &browse,
        started,
    ))
}

/// Collect an iterator of strings into a sorted, de-duplicated, length-capped
/// vector, dropping empties — the shape every filter-autocomplete value list
/// takes. The cap keeps the embedded data island small for huge registries.
fn distinct_capped(values: impl Iterator<Item = String>) -> Vec<String> {
    /// Maximum distinct values embedded per field for autocomplete.
    const VALUE_CAP: usize = 500;
    let mut out: Vec<String> = values.filter(|v| !v.is_empty()).collect();
    out.sort_unstable();
    out.dedup();
    out.truncate(VALUE_CAP);
    out
}

/// Display cap for the "required by" reverse-dependency list.
const REVERSE_DEP_CAP: usize = 100;

/// Resolve a package's forward and reverse closure for the detail page.
///
/// Forward dependencies come from the `refs` of the latest version's primary
/// platform (the platform that sorts first), resolved to package names via
/// [`Database::resolve_reference_names`]. Reverse dependencies come from
/// [`Database::reverse_dependencies`] keyed on the package's primary store
/// hash, capped to [`REVERSE_DEP_CAP`] entries for display while reporting the
/// full count.
///
/// # Errors
///
/// Returns an error on database failure.
async fn resolve_package_closure(
    db: &Database,
    registry_id: i64,
    name: &str,
    detail: &crate::db::PackageDetail,
) -> anyhow::Result<pages::PackageClosure> {
    // Forward deps: the latest version's first platform is the primary one.
    let primary = detail.versions.first().and_then(|v| v.platforms.first());
    let mut closure = pages::PackageClosure::default();
    if let Some(platform) = primary {
        closure.platform = Some(platform.platform.clone());
        let resolved = db
            .resolve_reference_names(registry_id, &platform.refs)
            .await?;
        closure.dependencies = resolved
            .into_iter()
            .map(|(hash, name, version)| pages::ResolvedDependency {
                hash,
                name,
                version,
            })
            .collect();
    }

    // Reverse deps: who references this package's primary store hash.
    let platform = primary.map(|p| p.platform.as_str()).unwrap_or("");
    if let Some(store_hash) = db.primary_store_hash(registry_id, name, platform).await? {
        let mut reverse = db.reverse_dependencies(registry_id, &store_hash).await?;
        closure.reverse_total = reverse.len();
        reverse.truncate(REVERSE_DEP_CAP);
        closure.reverse = reverse;
    }
    Ok(closure)
}

/// Build the shared [`ConsoleDeps`](aos_hub_core::web::console::ConsoleDeps) from
/// the hub's [`AppState`].
///
/// The native hub serves a nested-canonical registry's console pages through the
/// **shared** `aos_hub_core` console dispatcher (the single source of truth for
/// the console routing table), which needs these deps. The catch-all route
/// handlers carry only `state`, so this reconstructs the deps — all cheap `Arc`
/// clones over thin port wrappers — per call.
///
/// `default_storage_location` is `None` here: the nested dispatcher only serves
/// registry console pages, which never read it (it backs the instance-settings
/// page, served by the flat console router, where [`serve`] sets it explicitly).
fn console_deps(state: &Arc<AppState>) -> aos_hub_core::web::console::ConsoleDeps {
    aos_hub_core::web::console::ConsoleDeps {
        db: Arc::clone(&state.db),
        jwt_keys: state.auth.jwt_keys.clone(),
        external_url: state.external_url.clone(),
        dev: state.dev,
        ratelimit: Arc::clone(&state.ratelimit) as Arc<dyn aos_hub_core::ratelimit::RateLimiter>,
        mailer: Arc::clone(&state.mailer),
        sealer: Arc::clone(&state.sealer),
        http: Arc::new(crate::coreports::HubHttpClient::new(state.http.clone())),
        surface: Arc::new(
            crate::coreports::HubSurfaceProvider::new(Arc::clone(&state.db))
                .with_sealer(Arc::clone(&state.sealer)),
        ),
        surface_write: Arc::new(
            crate::coreports::HubSurfaceWriteProvider::new(Arc::clone(&state.db))
                .with_sealer(Arc::clone(&state.sealer)),
        ),
        reindexer: Arc::new(crate::coreports::HubReindexer::new(Arc::clone(&state.db))),
        default_storage_location: None,
        // The native hub's in-process database is already colocated and fast, so
        // it runs without a KV cache; token-revocation is immediate via the DB.
        kv: None,
    }
}

/// The `/{slug}/{*path}` route: a flat phase-1 machine path, or — when the
/// single-segment slug names no registry — the entry point to nested
/// canonical resolution.
///
/// Axum captures `acme/infra/prod/cdn/HEAD` here as `slug = "acme"`,
/// `path = "infra/prod/cdn/HEAD"` because a single-segment slug cannot span
/// `/`. So a flat registry resolves directly, and everything else
/// (including every nested registry and `/-/` page) falls through to
/// [`resolve_nested`] over the reconstructed full path.
async fn machine_path(
    State(state): State<Arc<AppState>>,
    Path((slug, path)): Path<(String, String)>,
    PeerAddr(peer): PeerAddr,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    match state.db.registry_by_slug(&slug).await {
        Ok(Some(registry)) => {
            if let Err(deny) = authorize_registry_read(&state, &registry, &headers).await {
                return *deny;
            }
            serve_registry_machine_path(&state, &registry, &path).await
        }
        // Not a flat registry: a nested-canonical registry's console `/-/`
        // page (its flat console routes capture only a single-segment slug),
        // else a nested machine/browse path.
        Ok(None) => {
            if let Some(response) = aos_hub_core::web::console::dispatch_nested(
                console_deps(&state),
                axum::http::Method::GET,
                uri.clone(),
                headers.clone(),
                axum::body::Bytes::new(),
            )
            .await
            {
                return response;
            }
            let nested = resolve_nested(&state, &uri, &headers, peer, Instant::now()).await;
            // A managed cache is tried last, so it can never shadow a flat or
            // nested registry (or console path) that shares the first URL
            // segment. NARs/narinfo are streamed from the cache surface
            // (Range-aware, never buffered into RAM); `nix-cache-info` is
            // generated from the cache's config.
            if nested.status() == StatusCode::NOT_FOUND {
                if let Ok(Some(cache)) = state.db.cache_by_slug(&slug).await {
                    // NAR explorer (native-only): `/{cache}/nar/<file>?explore`
                    // lists the archive's file tree instead of downloading. `nix`
                    // substitution never sends `?explore`. Gate + resolve the
                    // surface root here; everything else flows through the shared
                    // streaming serve below.
                    if path.starts_with("nar/")
                        && uri.query().is_some_and(|q| {
                            q.split('&')
                                .any(|kv| kv == "explore" || kv.starts_with("explore="))
                        })
                    {
                        if let Err(deny) = authorize_cache_read(&state, &cache, &headers).await {
                            return *deny;
                        }
                        let Some(root) = state.db.cache_surface_root(cache.id).await.ok().flatten()
                        else {
                            return StatusCode::NOT_FOUND.into_response();
                        };
                        return nar_explore_page(&slug, &root, &path).await;
                    }
                    // The ONE shared streaming cache-read path — identical code to
                    // the Worker: visibility gate, generated `nix-cache-info`,
                    // presigned-`302` for a private origin, and Range-aware
                    // streaming (a large NAR never buffers into memory).
                    let auth = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok());
                    let range = headers
                        .get(axum::http::header::RANGE)
                        .and_then(|v| v.to_str().ok());
                    return match crate::facade::write_service(&state)
                        .cache_serve(auth, &cache, &path, range)
                        .await
                    {
                        Ok(Some(resp)) => resp,
                        Ok(None) => StatusCode::NOT_FOUND.into_response(),
                        Err(err) => StatusCode::from_u16(err.http_status())
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
                            .into_response(),
                    };
                }
            }
            nested
        }
        Err(err) => internal(err),
    }
}

/// The `POST /{slug}/{*path}` route: a producer-console mutation on a
/// nested-canonical registry (`/-/settings/tokens`, `/-/channels/{name}/
/// console`, …).
///
/// A flat single-segment slug's console POSTs are served by the explicit
/// console routes; a nested registry's slug spans `/`, so its POSTs land
/// here and are dispatched to the shared
/// [`dispatch_nested`](aos_hub_core::web::console::dispatch_nested). Anything
/// that is not a recognized console path is a `404`.
async fn post_machine_path(
    State(state): State<Arc<AppState>>,
    Path((_slug, _path)): Path<(String, String)>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    match aos_hub_core::web::console::dispatch_nested(
        console_deps(&state),
        axum::http::Method::POST,
        uri,
        headers,
        body,
    )
    .await
    {
        Some(response) => response,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The `PUT /{slug}/{*path}` route: write one surface file to a managed
/// registry through the upload facade.
///
/// A flat single-segment slug that names a registry writes directly; any
/// other shape (a nested-canonical slug, or no flat match) is resolved by
/// longest registry-slug prefix and the remaining tail is the surface
/// path. The body extractor is last so axum buffers it only for the write
/// methods.
async fn put_machine_path(
    State(state): State<Arc<AppState>>,
    Path((slug, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    match resolve_write_target(&state, &slug, &path).await {
        Ok(Some((registry_slug, tail))) => {
            crate::facade::put_machine_path(&state, &registry_slug, &tail, &headers, body).await
        }
        // A managed cache: the shared `put_machine_path` has a cache branch
        // (content-addressed write + hosted-key narinfo signing), so
        // `nix copy --to <hub>/<cache>` works against caches too — mirroring the
        // HEAD handler's cache fallthrough.
        Ok(None) if matches!(state.db.cache_by_slug(&slug).await, Ok(Some(_))) => {
            crate::facade::put_machine_path(&state, &slug, &path, &headers, body).await
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// The `HEAD /{slug}/{*path}` route: probe whether a managed registry's
/// surface file exists, so an uploader can skip it.
async fn head_machine_path(
    State(state): State<Arc<AppState>>,
    Path((slug, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    match resolve_write_target(&state, &slug, &path).await {
        Ok(Some((registry_slug, tail))) => {
            crate::facade::head_machine_path(&state, &registry_slug, &tail, &headers).await
        }
        // A managed cache: the shared `head_machine_path` has a cache branch
        // (read-visibility + surface existence), so a substituter's `.narinfo`
        // HEAD probe works against caches too.
        Ok(None) if matches!(state.db.cache_by_slug(&slug).await, Ok(Some(_))) => {
            crate::facade::head_machine_path(&state, &slug, &path, &headers).await
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Resolve a `PUT`/`HEAD` request's `(slug, path)` capture into the target
/// registry slug and the surface-relative tail.
///
/// A flat slug that names a registry wins directly (tail = `path`);
/// otherwise the full `{slug}/{path}` is resolved by longest
/// registry-slug prefix, exactly as [`resolve_by_prefix`] does for reads.
/// `Ok(None)` means no registry owns the path.
///
/// # Errors
///
/// Returns an error on database failure.
async fn resolve_write_target(
    state: &AppState,
    slug: &str,
    path: &str,
) -> Result<Option<(String, String)>, anyhow::Error> {
    if state.db.registry_by_slug(slug).await?.is_some() {
        return Ok(Some((slug.to_string(), path.to_string())));
    }
    let full = format!("{slug}/{path}");
    let decoded = percent_decode(&full);
    match resolve_by_prefix(state, decoded.trim_end_matches('/')).await? {
        Some((registry, tail)) if !tail.is_empty() => Ok(Some((registry.slug, tail))),
        _ => Ok(None),
    }
}

/// Serve a machine path for a registry, resolving a managed registry's
/// surface from its storage binding.
///
/// Phase-1 `file://`/`http` registries carry their surface in `source_url`
/// and serve straight through [`compat::serve_machine_path`]. Managed
/// registries (empty `source_url`) instead resolve their on-disk surface
/// via [`crate::db::Database::registry_surface_root`]; the resolved path is
/// spliced into a `source_url` so the same byte-faithful facade serves it.
/// (The full managed upload/serve facade is phase 2d; this is the read
/// path the nested URL space needs now.)
async fn serve_registry_machine_path(
    state: &AppState,
    registry: &RegistryRecord,
    path: &str,
) -> Response {
    if !registry.source_url.is_empty() {
        return compat::serve_machine_path(registry, path).await;
    }
    match state.db.registry_surface_root(registry.id).await {
        Ok(Some(root)) => {
            let mut resolved = registry.clone();
            resolved.source_url = root.to_string_lossy().into_owned();
            let response = compat::serve_machine_path(&resolved, path).await;
            // Pull-through: a pullthrough mirror serving from an empty (or
            // partial) local binding fetches the missing path from upstream,
            // verifies it, persists content-addressed payloads, and serves it.
            if response.status() == StatusCode::NOT_FOUND {
                if let Some(pulled) = pull_through_machine_path(state, registry, &root, path).await
                {
                    return pulled;
                }
            }
            response
        }
        // No local surface (unbound managed registry): nothing to serve.
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Pull-through fetch-on-miss for a proxied pull-through mirror.
///
/// When `registry` is a `pullthrough` mirror, fetches the missing machine
/// `path` from its upstream, verifies it (loose objects by oid; narinfos by
/// `Sig:` against the registry's trust roster; NARs by hash against their
/// verified narinfo; pointers fetched live and not frozen), persists the
/// hash-checked objects into the binding `root`, and serves the bytes with the
/// path's machine cache-control. Returns `None` when the registry is not a
/// pull-through mirror, the path is not a machine path, or the upstream lacks
/// it — letting the caller fall back to its `404`. A verification failure or
/// upstream error maps to `502 Bad Gateway` so a tampered narinfo/NAR is
/// refused rather than proxied, and the proxy never hangs or 500s.
async fn pull_through_machine_path(
    state: &AppState,
    registry: &RegistryRecord,
    root: &std::path::Path,
    path: &str,
) -> Option<Response> {
    if !compat::is_machine_path(path) {
        return None;
    }
    let source = match state.db.mirror_source(registry.id).await {
        Ok(Some(source)) if source.mode == "pullthrough" => source,
        Ok(_) => return None,
        Err(err) => return Some(internal(err)),
    };
    // Defense in depth: a pull-through fetch reaches out over the network, so
    // re-validate the configured upstream is a safe remote target before each
    // request (creation already validated it).
    if let Err(err) = crate::fetch::is_safe_remote_url(&source.upstream_url) {
        return Some(internal(err));
    }
    let fetch = match crate::fetch::fetch_for_url(&source.upstream_url).await {
        Ok(fetch) => fetch,
        Err(err) => return Some(internal(err)),
    };
    match crate::mirror::fetch_through(
        fetch.as_ref(),
        root,
        path,
        &registry.trust_keys,
        source.verify,
    )
    .await
    {
        Ok(Some(result)) => {
            let mut response = result.bytes.into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(compat::content_type(path)),
            );
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(compat::cache_control(path)),
            );
            Some(response)
        }
        // Upstream definitively lacks the path: fall back to the local 404.
        Ok(None) => None,
        Err(err) => {
            tracing::warn!(
                slug = %registry.slug,
                %path,
                error = %format!("{err:#}"),
                "pull-through fetch failed"
            );
            Some(StatusCode::BAD_GATEWAY.into_response())
        }
    }
}

/// The page kind a registry URL's `/-/` namespace addresses.
enum PageKind {
    Home,
    Packages,
    Package(String),
    Channels,
    Channel(String),
    Releases,
    Health,
}

/// Resolve a request path into `(registry, page-or-machine)` for the
/// nested-canonical URL space, then render it with visibility enforced.
///
/// This is the catch-all for registries whose slug contains slashes
/// (`acme/infra/prod/cdn`) — axum single-segment routes cannot match them,
/// so the flat `/{slug}/…` routes above only serve phase-1 registries. The
/// path is split on the reserved `/-/` marker: the left side (trailing
/// slash trimmed) is the registry's canonical path and the right side is a
/// human page. With no `/-/`, the path resolves by longest registry-slug
/// prefix — an exact match is the registry home, and any remainder is a
/// machine path served through the facade.
async fn nested_catch_all(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    PeerAddr(peer): PeerAddr,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // The fallback receives every method; route the upload facade's
    // PUT/HEAD to a nested registry's surface, and everything else to the
    // read resolver — but first give the producer console a chance to claim
    // a nested-canonical `/-/` console path (its flat routes only capture a
    // single-segment slug, so nested registries land here).
    match method {
        axum::http::Method::PUT | axum::http::Method::HEAD => {
            resolve_nested_write(&state, &method, &uri, &headers, body).await
        }
        axum::http::Method::GET | axum::http::Method::POST => {
            if let Some(response) = aos_hub_core::web::console::dispatch_nested(
                console_deps(&state),
                method.clone(),
                uri.clone(),
                headers.clone(),
                body,
            )
            .await
            {
                return response;
            }
            resolve_nested(&state, &uri, &headers, peer, Instant::now()).await
        }
        _ => resolve_nested(&state, &uri, &headers, peer, Instant::now()).await,
    }
}

/// Resolve a nested-canonical `PUT`/`HEAD` into the write facade.
///
/// Splits the request path by longest registry-slug prefix (the same rule
/// reads use) and dispatches the surface tail to [`crate::facade`]. A path
/// that resolves to a registry home (empty tail) or names no registry is a
/// `404`.
async fn resolve_nested_write(
    state: &AppState,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let decoded = percent_decode(uri.path().trim_start_matches('/'));
    let target = match resolve_by_prefix(state, decoded.trim_end_matches('/')).await {
        Ok(Some((registry, tail))) if !tail.is_empty() => (registry.slug, tail),
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    let (slug, tail) = target;
    if method == axum::http::Method::PUT {
        crate::facade::put_machine_path(state, &slug, &tail, headers, body).await
    } else {
        crate::facade::head_machine_path(state, &slug, &tail, headers).await
    }
}

/// Resolve and render a request in the nested-canonical URL space.
///
/// Shared by [`nested_catch_all`] (the router fallback) and the
/// `/{slug}/{*path}` handler when its flat slug names no registry. See
/// [`nested_catch_all`] for the splitting rules.
async fn resolve_nested(
    state: &AppState,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    started: Instant,
) -> Response {
    let raw = uri.path().trim_start_matches('/');
    let decoded = percent_decode(raw);

    // Human pages live behind the reserved `/-/` marker.
    if let Some((left, right)) = decoded.split_once("/-/") {
        let slug = left.trim_end_matches('/');
        let page = match parse_page(right) {
            Some(page) => page,
            None => return StatusCode::NOT_FOUND.into_response(),
        };
        // Parse the query by hand: this nested path has no axum `Query`
        // extractor, so the package index's search/filter/sort/page controls
        // would otherwise be silently dropped on org-scoped registry URLs.
        let params = SearchParams::from_query(uri.query());
        return match state.db.registry_by_slug(slug).await {
            Ok(Some(registry)) => {
                if let Err(deny) = authorize_registry_read(state, &registry, headers).await {
                    return *deny;
                }
                render_page(state, &registry, page, &params, headers, peer, started).await
            }
            Ok(None) => StatusCode::NOT_FOUND.into_response(),
            Err(err) => internal(err),
        };
    }

    // No `/-/`: either a registry home (exact slug, trailing slash trimmed)
    // or a machine path (slug + remainder). Resolve by longest slug prefix.
    let trimmed = decoded.trim_end_matches('/');
    match resolve_by_prefix(state, trimmed).await {
        Ok(Some((registry, tail))) => {
            if let Err(deny) = authorize_registry_read(state, &registry, headers).await {
                return *deny;
            }
            if tail.is_empty() {
                let params = SearchParams::from_query(uri.query());
                render_page(
                    state,
                    &registry,
                    PageKind::Home,
                    &params,
                    headers,
                    peer,
                    started,
                )
                .await
            } else {
                serve_registry_machine_path(state, &registry, &tail).await
            }
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Parse the portion of a URL after the `/-/` marker into a [`PageKind`].
fn parse_page(rest: &str) -> Option<PageKind> {
    let rest = rest.trim_end_matches('/');
    match rest {
        "packages" => Some(PageKind::Packages),
        "channels" => Some(PageKind::Channels),
        "releases" => Some(PageKind::Releases),
        "health" => Some(PageKind::Health),
        _ => {
            if let Some(name) = rest.strip_prefix("packages/") {
                (!name.contains('/')).then(|| PageKind::Package(name.to_string()))
            } else if let Some(name) = rest.strip_prefix("channels/") {
                (!name.contains('/')).then(|| PageKind::Channel(name.to_string()))
            } else {
                None
            }
        }
    }
}

/// Resolve the longest registry slug that is a path-segment prefix of
/// `path`, returning the registry and the remaining machine-path tail.
///
/// `acme/infra/prod/cdn/objects/ab` resolves to registry
/// `acme/infra/prod/cdn` with tail `objects/ab`; an exact match yields an
/// empty tail (the registry home). Matching is on `/` boundaries, so
/// `acme/infra/prod/cdn-staging` never resolves to `acme/infra/prod/cdn`.
pub(crate) async fn resolve_by_prefix(
    state: &AppState,
    path: &str,
) -> Result<Option<(RegistryRecord, String)>, anyhow::Error> {
    let mut candidate = path;
    loop {
        if let Some(registry) = state.db.registry_by_slug(candidate).await? {
            let tail = path[candidate.len()..].trim_start_matches('/').to_string();
            return Ok(Some((registry, tail)));
        }
        match candidate.rsplit_once('/') {
            Some((head, _)) => candidate = head,
            None => return Ok(None),
        }
    }
}

/// Render one registry page, reusing the same renderers as the flat routes.
///
/// `params` carries the parsed query string; only [`PageKind::Packages`] reads
/// it (for search/filter/sort/page), but it is threaded through uniformly so
/// the nested-canonical path honors the same controls as the flat route.
async fn render_page(
    state: &AppState,
    registry: &RegistryRecord,
    page: PageKind,
    params: &SearchParams,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    started: Instant,
) -> Response {
    // The org-scoped (`org/registry/-/…`) URLs reach the package browser and
    // registry home through here rather than the flat routes; throttle the
    // same expensive, anonymous page kinds per IP so this path is no weaker.
    if matches!(page, PageKind::Home | PageKind::Packages) {
        if let Some(limited) = browse_rate_limited(state, headers, peer) {
            return limited;
        }
    }
    let status = match state.db.index_status(registry.id).await {
        Ok(status) => status,
        Err(err) => return internal(err),
    };
    let result = async {
        Ok::<_, anyhow::Error>(match &page {
            PageKind::Home => {
                Some(render_home(state, registry, status.as_ref(), headers, started).await?)
            }
            PageKind::Packages => {
                Some(package_index_html(state, registry, status.as_ref(), params, started).await?)
            }
            PageKind::Package(name) => match state.db.package_detail(registry.id, name).await? {
                Some(detail) => {
                    let closure =
                        resolve_package_closure(&state.db, registry.id, name, &detail).await?;
                    Some(pages::package_page(
                        registry,
                        status.as_ref(),
                        &detail,
                        &closure,
                        &state.external_url,
                        started,
                    ))
                }
                None => None,
            },
            PageKind::Channels => {
                let channels = state.db.list_channels(registry.id).await?;
                Some(pages::channels_index(
                    registry,
                    status.as_ref(),
                    &channels,
                    params.page_number(),
                    started,
                ))
            }
            PageKind::Channel(name) => {
                let channels = state.db.list_channels(registry.id).await?;
                match channels.into_iter().find(|c| &c.name == name) {
                    Some(channel) => {
                        let floor = state.db.channel_floor(registry.id, name).await?;
                        Some(pages::channel_page(
                            registry,
                            status.as_ref(),
                            &channel,
                            floor.as_deref(),
                            None,
                            started,
                        ))
                    }
                    None => None,
                }
            }
            PageKind::Releases => {
                let releases = state.db.list_releases(registry.id).await?;
                Some(pages::releases_page(
                    registry,
                    status.as_ref(),
                    &releases,
                    params.page_number(),
                    started,
                ))
            }
            PageKind::Health => {
                let mut runs = Vec::new();
                for run in state.db.latest_validation_runs(registry.id).await? {
                    let missing = if run.missing > 0 {
                        state.db.validation_missing(run.id).await?
                    } else {
                        Vec::new()
                    };
                    let corrupt = if run.missing > 0 {
                        state.db.validation_corrupt(run.id).await?
                    } else {
                        Vec::new()
                    };
                    runs.push((run, missing, corrupt));
                }
                let stack = state.db.registry_cache_stack(registry.id).await?;
                let probes = state.db.list_cache_probes(registry.id).await?;
                let repair_jobs = state
                    .db
                    .list_repair_jobs(registry.id, HEALTH_REPAIR_JOB_LIMIT)
                    .await?;
                let frontends = state.db.list_frontends(registry.id).await?;
                let frontend_probes = state.db.list_frontend_probes(registry.id).await?;
                Some(pages::health_page(
                    registry,
                    status.as_ref(),
                    &runs,
                    stack.as_ref(),
                    &probes,
                    &repair_jobs,
                    &frontends,
                    &frontend_probes,
                    started,
                ))
            }
        })
    }
    .await;
    let _ = headers;
    respond_page(result)
}

/// Render a registry home page (shared by flat and nested routes).
async fn render_home(
    state: &AppState,
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    headers: &HeaderMap,
    started: Instant,
) -> Result<String, anyhow::Error> {
    let channels = state.db.list_channels(registry.id).await?;
    let packages = state.db.list_packages(registry.id).await?;
    let caches = state.db.list_advertised_caches(registry.id).await?;
    let roster = state.db.list_roster(registry.id).await?;
    let validations = state.db.latest_validation_runs(registry.id).await?;
    let external = format!(
        "{}/{}",
        state.external_url.trim_end_matches('/'),
        registry.slug
    );
    Ok(pages::registry_home(
        registry,
        status,
        &channels,
        &packages,
        &caches,
        &roster,
        &validations,
        &external,
        registry_manage_link(state, registry, headers).await,
        started,
    ))
}

/// Whether the request's session user may *manage* `registry` — i.e. holds
/// `registry.configure` at its canonical scope — so the registry home renders
/// the "manage this registry" link.
///
/// Returns `false` for an anonymous request or any database error: the link is
/// a pure discoverability affordance, so a lookup failure quietly hides it.
async fn registry_manage_link(
    state: &AppState,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> bool {
    let Some(secret) = session_secret_from_cookies(headers) else {
        return false;
    };
    let Ok(Some(session)) = state.db.validate_session(&secret).await else {
        return false;
    };
    let Ok(grants) = state
        .db
        .effective_scopes(crate::domain::Principal::user(session.user_id))
        .await
    else {
        return false;
    };
    crate::domain::iam::allow(
        &grants,
        crate::domain::Permission::RegistryConfigure,
        &crate::domain::Scope::parse(&registry.slug),
    )
}

/// Authorize a read against a registry's visibility, or return the denial.
///
/// - **public** (and every phase-1 unowned registry) — anonymous reads pass.
/// - **internal** — requires a valid session whose user is a member of the
///   owning org (any role, via an effective grant at or above the org scope).
/// - **private** — requires `Read` at the registry's canonical scope, held
///   either by the session user's current memberships or by a bearer JWT.
///
/// Unauthorized `internal`/`private` reads return **404, not 403**, so the
/// existence of a hidden registry is never disclosed. The check reads the
/// session cookie and `Authorization` header directly from `headers` (it is
/// not an extractor) so it composes inside the catch-all and the flat
/// handlers alike.
///
/// # Errors
///
/// Returns the denial [`Response`] (a 404) in the `Err` arm when the read is
/// not authorized; `Ok(())` means the caller may proceed. The denial is
/// boxed to keep the common `Ok` path small.
pub(crate) async fn authorize_registry_read(
    state: &AppState,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    let denied = || Box::new(StatusCode::NOT_FOUND.into_response());
    // A registry owned by a soft-deleted org stops serving entirely (RFC-0004
    // offboarding): 404, never disclosing that it once existed.
    if let Some(org_id) = registry.org_id {
        if !matches!(state.db.org_is_active(org_id).await, Ok(true)) {
            return Err(denied());
        }
    }
    match registry.visibility.as_str() {
        // Public (and any unowned phase-1 registry) is always readable.
        "public" => Ok(()),
        "internal" => {
            let Some(org_id) = registry.org_id else {
                return Ok(());
            };
            if session_is_org_member(state, headers, org_id).await {
                Ok(())
            } else {
                Err(denied())
            }
        }
        // Private (or any unknown visibility, fail closed): require Read on
        // the registry scope from a session or a bearer token.
        _ => {
            let scope = Scope::parse(&registry.slug);
            if session_allows_read(state, headers, &scope).await
                || bearer_allows_read(state, headers, &scope)
            {
                Ok(())
            } else {
                Err(denied())
            }
        }
    }
}

/// Whether the request's session user holds any membership covering `org_id`.
/// Whether this caller may read `cache` — the cache analog of
/// [`authorize_registry_read`]: a tombstoned cache or one under a suspended org
/// is `404`; `public` is open; `internal` requires org membership; `private`
/// requires `read` on the owning org scope (or root for an instance-level
/// cache). Returns the `404` response to send on denial.
pub(crate) async fn authorize_cache_read(
    state: &AppState,
    cache: &crate::db::Cache,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    let denied = || Box::new(StatusCode::NOT_FOUND.into_response());
    if cache.deleted_at.is_some() {
        return Err(denied());
    }
    if let Some(org_id) = cache.org_id {
        if !matches!(state.db.org_is_active(org_id).await, Ok(true)) {
            return Err(denied());
        }
    }
    match cache.visibility.as_str() {
        "public" => Ok(()),
        "internal" => match cache.org_id {
            None => Ok(()),
            Some(org_id) => {
                if session_is_org_member(state, headers, org_id).await {
                    Ok(())
                } else {
                    Err(denied())
                }
            }
        },
        _ => {
            let scope = match cache.org_id {
                Some(org_id) => match state.db.org_by_id(org_id).await.ok().flatten() {
                    Some(org) => Scope::parse(&org.slug),
                    None => return Err(denied()),
                },
                None => Scope::root(),
            };
            if session_allows_read(state, headers, &scope).await
                || bearer_allows_read(state, headers, &scope)
            {
                Ok(())
            } else {
                Err(denied())
            }
        }
    }
}

/// Maximum decompressed NAR size accepted by the explorer — a decompression-bomb
/// guard shared by every codec.
const MAX_DECOMPRESSED_NAR: usize = 512 * 1024 * 1024;

/// A `Write` sink that errors once more than `cap` bytes are written, so a
/// decompressor (which streams into it) cannot exhaust memory on a bomb.
struct CappedWriter {
    buf: Vec<u8>,
    cap: usize,
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() + data.len() > self.cap {
            return Err(std::io::Error::other(
                "decompressed NAR exceeds explorer size cap",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Decompress a stored cache NAR by its URL extension, bounding the output so a
/// decompression bomb cannot exhaust memory.
fn decompress_nar(raw: &[u8], rel: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::Read as _;
    let cap = MAX_DECOMPRESSED_NAR;
    if rel.ends_with(".nar.zst") || rel.ends_with(".zst") {
        let mut out = Vec::new();
        zstd::stream::Decoder::new(raw)?
            .take(cap as u64)
            .read_to_end(&mut out)?;
        Ok(out)
    } else if rel.ends_with(".nar.xz") || rel.ends_with(".xz") {
        let mut sink = CappedWriter {
            buf: Vec::new(),
            cap,
        };
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(raw), &mut sink)?;
        Ok(sink.buf)
    } else if rel.ends_with(".nar") {
        if raw.len() > cap {
            anyhow::bail!("NAR exceeds explorer size cap");
        }
        Ok(raw.to_vec())
    } else {
        anyhow::bail!("unsupported NAR compression for '{rel}'")
    }
}

/// Render a NAR's internal file tree as a no-JS page (the NAR explorer).
///
/// Native-only: it reads, decompresses, and parses the archive
/// ([`crate::narlist`]). A too-large NAR or an unsupported compression shows a
/// note with the whole-NAR download link rather than failing.
async fn nar_explore_page(slug: &str, root: &std::path::Path, rel: &str) -> Response {
    use aos_hub_core::web::render::escape;
    const MAX_COMPRESSED: u64 = 128 * 1024 * 1024;

    let Ok(target) = crate::fetch::safe_join(root, rel) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let download = format!("/{}/{}", slug, rel);
    let note = |msg: String| {
        axum::response::Html(format!(
            "<!DOCTYPE html><html><head><meta charset=utf-8>\
             <link rel=stylesheet href=/_assets/style.css><title>NAR</title></head>\
             <body><h1>NAR contents</h1><p>{msg}</p>\
             <p><a href=\"{}\">download whole NAR</a></p></body></html>",
            escape(&download),
        ))
        .into_response()
    };

    // Symlink containment: the resolved file must stay under the surface root
    // (the same guard `cache_serve_file` applies to the download path).
    let (Ok(real_root), Ok(real_target)) = (
        tokio::fs::canonicalize(root).await,
        tokio::fs::canonicalize(&target).await,
    ) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !real_target.starts_with(&real_root) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(meta) = tokio::fs::metadata(&real_target).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if meta.len() > MAX_COMPRESSED {
        return note(format!("NAR too large to explore ({} bytes).", meta.len()));
    }
    let Ok(raw) = tokio::fs::read(&real_target).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let decompressed = match decompress_nar(&raw, rel) {
        Ok(d) => d,
        Err(err) => return note(format!("cannot explore: {}", escape(&format!("{err:#}")))),
    };
    let entries = match crate::narlist::list_nar(&decompressed) {
        Ok(e) => e,
        Err(err) => return note(format!("not a valid NAR: {}", escape(&format!("{err:#}")))),
    };

    let mut rows = String::new();
    for e in &entries {
        let size = if e.kind == "directory" || e.kind == "symlink" {
            String::new()
        } else {
            e.size.to_string()
        };
        let kind = match &e.target {
            Some(t) => format!("{} → {}", e.kind, escape(t)),
            None => e.kind.to_string(),
        };
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            escape(&e.path),
            kind,
            size,
        ));
    }
    axum::response::Html(format!(
        "<!DOCTYPE html><html><head><meta charset=utf-8>\
         <link rel=stylesheet href=/_assets/style.css><title>NAR · {slug}</title></head>\
         <body><h1>NAR contents</h1>\
         <p><a href=\"{dl}\">download whole NAR</a> · {n} entries</p>\
         <table><thead><tr><th>path</th><th>kind</th><th>size</th></tr></thead>\
         <tbody>{rows}</tbody></table></body></html>",
        slug = escape(slug),
        dl = escape(&download),
        n = entries.len(),
        rows = rows,
    ))
    .into_response()
}

async fn session_is_org_member(state: &AppState, headers: &HeaderMap, org_id: i64) -> bool {
    let Some(org) = state.db.org_by_id(org_id).await.ok().flatten() else {
        return false;
    };
    let scope = Scope::parse(&org.slug);
    session_allows_read(state, headers, &scope).await
}

/// Whether the request's session user may `Read` at `scope` under their
/// current memberships.
async fn session_allows_read(state: &AppState, headers: &HeaderMap, scope: &Scope) -> bool {
    let Some(secret) = session_secret_from_cookies(headers) else {
        return false;
    };
    let Ok(Some(session)) = state.db.validate_session(&secret).await else {
        return false;
    };
    crate::auth::extract::session_allows(&state.db, &session, Permission::Read, scope)
        .await
        .unwrap_or(false)
}

/// Whether a bearer JWT in `headers` grants `Read` at `scope`.
fn bearer_allows_read(state: &AppState, headers: &HeaderMap, scope: &Scope) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    match state.auth.jwt_keys.verify(token) {
        Ok(claims) => crate::auth::extract::token_allows(&claims, Permission::Read, scope),
        Err(_) => false,
    }
}

/// Extract the `__Host-aos_session` cookie value from a request's headers.
///
/// A thin wrapper over the runtime-neutral
/// [`aos_hub_core::web::session::session_secret_from_headers`] so the hub
/// and the Worker parse the cookie identically.
pub(crate) fn session_secret_from_cookies(headers: &HeaderMap) -> Option<String> {
    aos_hub_core::web::session::session_secret_from_headers(headers)
}

/// Percent-decode a URL path, leaving invalid sequences as-is.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Hex digit value, or `None` for a non-hex byte.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn respond_page(result: Result<Option<String>, anyhow::Error>) -> Response {
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}
