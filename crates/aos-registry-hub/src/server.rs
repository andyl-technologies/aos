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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;

use crate::auth::extract::AuthState;
use crate::compat;
use crate::db::{Database, IndexStatus, PackageRow, RegistryRecord};
use crate::domain::{Permission, Principal, Scope};
use crate::ui::{pages, APP_JS, STYLESHEET};

/// Lifetime, in seconds, of a hub access token minted at `/oauth2/token`.
const ACCESS_TOKEN_TTL_SECS: i64 = 900;

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
    pub leases: crate::facade::LeaseMap,
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
    pub fn new(db: Arc<Database>, external_url: String) -> AppState {
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
            leases: crate::facade::LeaseMap::new(),
            mailer: Arc::new(crate::auth::magic::LogMailer),
            dev: false,
            // A deterministic placeholder sealer for dev/tests; production
            // supplies a real one via the struct literal.
            sealer: crate::auth::oidc::dev_sealer(),
            http: crate::fetch::hardened_client(),
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

impl crate::validation::RepairAuthorizer for HubRepairAuthorizer {
    fn credential_for(
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
        let Some(registry) = self.db.registry_by_slug(slug)? else {
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
            .mint(&auth, crate::rpc::UPLOAD_CREDENTIAL_TTL_SECS)?;
        Ok(Some(crate::validation::RepairCredential {
            upload_url: format!("{base}/{}", registry.slug),
            bearer_jwt: jwt,
        }))
    }
}

/// Optional search/pagination query parameters (`?q=`, `?page=`).
#[derive(Debug, Default, serde::Deserialize)]
struct SearchParams {
    q: Option<String>,
    page: Option<usize>,
    /// Package-index sort order (`name`, `size`, `version`); unknown values
    /// fall back to name order.
    sort: Option<String>,
    /// Package-index license facet (exact SPDX identifier match).
    license: Option<String>,
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

    /// The trimmed, non-empty license facet, if any.
    fn license(&self) -> Option<&str> {
        self.license
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty())
    }
}

/// Build the complete hub router.
///
/// `aos.registry.v1` ConnectRPC method paths are static two-segment
/// routes (`/aos.registry.v1.RegistryService/ListRegistries`), so axum's
/// static-over-dynamic precedence keeps them from being shadowed by the
/// `/{slug}/{*path}` facade wildcard.
pub fn router(state: Arc<AppState>) -> Router {
    use aos_proto::aos::registry::v1::{
        AuditServiceExt, ChannelServiceExt, ConfigServiceExt, GitServiceExt, OrgServiceExt,
        PackageServiceExt, ProjectServiceExt, PublishServiceExt, RegistryServiceExt,
        StorageServiceExt, WebhookServiceExt,
    };
    let rpc = Arc::new(crate::rpc::RegistryRpc {
        db: Arc::clone(&state.db),
        jwt_keys: state.auth.jwt_keys.clone(),
        external_url: state.external_url.clone(),
    });
    let connect_router = connectrpc::Router::new();
    let connect_router = RegistryServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = OrgServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = ProjectServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = StorageServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = AuditServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = ConfigServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = PackageServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = ChannelServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = PublishServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = GitServiceExt::register(Arc::clone(&rpc), connect_router);
    let connect_router = WebhookServiceExt::register(rpc, connect_router);
    let connect_paths: Vec<String> = connect_router
        .methods()
        .map(|method| format!("/{method}"))
        .collect();
    let connect_service = connect_router.into_axum_service();

    // The `/oauth2/token` exchange fragment runs on Arc<AuthState>; bind its
    // state up front so it merges into the AppState-typed router below.
    let oauth2 = crate::auth::extract::oauth2_router().with_state(Arc::clone(&state.auth));

    let mut router = Router::new()
        .route("/", get(instance_home))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route(
            "/oauth2/device_authorization",
            axum::routing::post(device_authorization),
        )
        .route("/_assets/style.css", get(stylesheet))
        .route("/_assets/app.js", get(app_js))
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
        .route(
            "/{slug}/{*path}",
            get(machine_path)
                .post(post_machine_path)
                .put(put_machine_path)
                .head(head_machine_path),
        );
    for path in connect_paths {
        router = router.route_service(&path, connect_service.clone());
    }
    // The nested-canonical catch-all is registered last: axum's
    // static-over-dynamic precedence keeps the explicit routes above
    // (healthz, _assets, oauth2, RPC method paths, the flat `/{slug}` shapes)
    // winning, and only requests matching none of them reach the resolver.
    // The fallback handles every method so nested-canonical registries
    // (slugs with slashes) accept the upload facade's PUT/HEAD too.
    router = router.fallback(nested_catch_all);
    router
        // The producer console: session login, account, device approval, org
        // dashboards, and per-registry management. Its static prefixes
        // (/login, /account, /activate, /-/org…, /{slug}/-/settings…) win
        // over the registry catch-all by static-over-dynamic precedence.
        .merge(crate::console::router())
        .merge(oauth2)
        // Resolve the request's session once and put the user's email in a
        // task-local, so every page's masthead reflects the login + shows
        // navigation without threading the identity through each handler.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            resolve_session,
        ))
        .with_state(state)
        // Panics become plain 500s instead of dropped connections; the
        // security-header layer wraps everything (including those 500s).
        .layer(CatchPanicLayer::new())
        .layer(axum::middleware::from_fn(security_headers))
}

/// Resolve the current session and run the request with the user's email in
/// a task-local (read by the page renderer's masthead).
async fn resolve_session(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let email = session_secret_from_cookies(request.headers())
        .and_then(|secret| state.db.session_email(&secret).ok().flatten());
    crate::ui::render::with_session_email(email, next.run(request)).await
}

/// Stamp the first-party security headers onto every response.
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // Default policy is `default-src 'self'` (no inline scripts). The passkey
    // pages are the one no-JS exception (WebAuthn requires `navigator.
    // credentials`): they set their own per-request CSP carrying a nonce in
    // `script-src` before this layer runs, so honor a handler-set CSP rather
    // than clobbering it. Every other response gets the strict default.
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert_with(|| HeaderValue::from_static("default-src 'self'"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
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

pub(crate) fn load_registry(
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
    match state.db.start_device_authorization(&scope, &perms) {
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
/// per-`state` breakdown, the webhook-delivery queue depth by lifecycle, and a
/// `build_info` gauge carrying the crate version as a label. Every series is
/// preceded by its `# HELP`/`# TYPE` lines.
///
/// [exposition format]: https://prometheus.io/docs/instrumenting/exposition_formats/
async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let body = match render_metrics(&state) {
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
fn render_metrics(state: &AppState) -> Result<String, anyhow::Error> {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let registries = state.db.list_registries()?;
    let mut by_state: BTreeMap<String, u64> = BTreeMap::new();
    for registry in &registries {
        let label = state
            .db
            .index_status(registry.id)?
            .map(|s| s.state)
            .unwrap_or_else(|| "indexing".to_string());
        *by_state.entry(label).or_default() += 1;
    }
    let (pending, delivered, failed) = state.db.delivery_status_counts()?;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP aos_registry_hub_registries_total Registered registries.\n\
         # TYPE aos_registry_hub_registries_total gauge\n\
         aos_registry_hub_registries_total {}",
        registries.len()
    );
    let _ = writeln!(
        out,
        "# HELP aos_registry_hub_registries_by_state Registered registries by index state.\n\
         # TYPE aos_registry_hub_registries_by_state gauge"
    );
    // Always emit the four known states (zero when absent) so a scrape never
    // loses a series, then any other state the index reports.
    for known in ["fresh", "indexing", "stale", "failed"] {
        let n = by_state.remove(known).unwrap_or(0);
        let _ = writeln!(
            out,
            "aos_registry_hub_registries_by_state{{state=\"{known}\"}} {n}"
        );
    }
    for (extra, n) in &by_state {
        let _ = writeln!(
            out,
            "aos_registry_hub_registries_by_state{{state=\"{extra}\"}} {n}"
        );
    }
    let _ = writeln!(
        out,
        "# HELP aos_registry_hub_webhook_deliveries Webhook deliveries by status.\n\
         # TYPE aos_registry_hub_webhook_deliveries gauge\n\
         aos_registry_hub_webhook_deliveries{{status=\"pending\"}} {pending}\n\
         aos_registry_hub_webhook_deliveries{{status=\"delivered\"}} {delivered}\n\
         aos_registry_hub_webhook_deliveries{{status=\"failed\"}} {failed}"
    );
    let _ = writeln!(
        out,
        "# HELP aos_registry_hub_build_info Build information.\n\
         # TYPE aos_registry_hub_build_info gauge\n\
         aos_registry_hub_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    Ok(out)
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

async fn app_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        APP_JS,
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
    headers: HeaderMap,
    Query(params): Query<SearchParams>,
) -> Response {
    let started = Instant::now();
    let result = (|| {
        let mut rows = Vec::new();
        for registry in state.db.list_registries()? {
            // Non-disclosure: only list registries this caller could open.
            // Anonymous callers see public only; a session/token member sees
            // their org's internal and any granted private registries too.
            if !can_read_registry(&state, &registry, &headers) {
                continue;
            }
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
        let manage_link = registry_manage_link(&state, &registry, &headers);
        Ok::<_, anyhow::Error>(Some(pages::registry_home(
            &registry,
            status.as_ref(),
            &channels,
            &packages,
            &caches,
            &roster,
            &validations,
            &external,
            manage_link,
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
        let license = params.license();
        let sort = pages::PackageSort::parse(params.sort.as_deref());
        // The `?q=` substring matches name, description, and license; the
        // `?license=` facet is an exact (case-insensitive) license match.
        let mut filtered: Vec<PackageRow> = all
            .into_iter()
            .filter(|p| match query {
                None => true,
                Some(query) => {
                    let needle = query.to_lowercase();
                    p.name.to_lowercase().contains(&needle)
                        || p.description.to_lowercase().contains(&needle)
                        || p.license.to_lowercase().contains(&needle)
                }
            })
            .filter(|p| match license {
                None => true,
                Some(license) => p.license.eq_ignore_ascii_case(license),
            })
            .collect();
        match sort {
            pages::PackageSort::Name => {}
            pages::PackageSort::Size => filtered.sort_by(|a, b| {
                b.closure_size
                    .unwrap_or(0)
                    .cmp(&a.closure_size.unwrap_or(0))
                    .then_with(|| a.name.cmp(&b.name))
            }),
            pages::PackageSort::Version => filtered.sort_by(|a, b| {
                b.latest_version
                    .cmp(&a.latest_version)
                    .then_with(|| a.name.cmp(&b.name))
            }),
        }
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
            sort,
            license,
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
        let closure = resolve_package_closure(&state.db, registry.id, &name, &detail)?;
        Ok::<_, anyhow::Error>(Some(pages::package_page(
            &registry,
            status.as_ref(),
            &detail,
            &closure,
            &state.external_url,
            started,
        )))
    })();
    respond_page(result)
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
fn resolve_package_closure(
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
        let resolved = db.resolve_reference_names(registry_id, &platform.refs)?;
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
    if let Some(store_hash) = db.primary_store_hash(registry_id, name, platform)? {
        let mut reverse = db.reverse_dependencies(registry_id, &store_hash)?;
        closure.reverse_total = reverse.len();
        reverse.truncate(REVERSE_DEP_CAP);
        closure.reverse = reverse;
    }
    Ok(closure)
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
            // Deep runs can also carry `corrupt` findings; load them so the
            // page flags corruption distinctly from absence.
            let corrupt = if run.missing > 0 {
                state.db.validation_corrupt(run.id)?
            } else {
                Vec::new()
            };
            runs.push((run, missing, corrupt));
        }
        let stack = state.db.registry_cache_stack(registry.id)?;
        let probes = state.db.list_cache_probes(registry.id)?;
        let repair_jobs = state
            .db
            .list_repair_jobs(registry.id, HEALTH_REPAIR_JOB_LIMIT)?;
        let frontends = state.db.list_frontends(registry.id)?;
        let frontend_probes = state.db.list_frontend_probes(registry.id)?;
        Ok::<_, anyhow::Error>(Some(pages::health_page(
            &registry,
            status.as_ref(),
            &runs,
            stack.as_ref(),
            &probes,
            &repair_jobs,
            &frontends,
            &frontend_probes,
            started,
        )))
    })();
    respond_page(result)
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
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    match state.db.registry_by_slug(&slug) {
        Ok(Some(registry)) => {
            if let Err(deny) = authorize_registry_read(&state, &registry, &headers) {
                return *deny;
            }
            serve_registry_machine_path(&state, &registry, &path).await
        }
        // Not a flat registry: a nested-canonical registry's console `/-/`
        // page (its flat console routes capture only a single-segment slug),
        // else a nested machine/browse path.
        Ok(None) => {
            if let Some(response) = crate::console::dispatch_nested(
                &state,
                &axum::http::Method::GET,
                &uri,
                &headers,
                axum::body::Bytes::new(),
            )
            .await
            {
                return response;
            }
            resolve_nested(&state, &uri, &headers, Instant::now()).await
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
/// here and are dispatched to [`crate::console::dispatch_nested`]. Anything
/// that is not a recognized console path is a `404`.
async fn post_machine_path(
    State(state): State<Arc<AppState>>,
    Path((_slug, _path)): Path<(String, String)>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    match crate::console::dispatch_nested(&state, &axum::http::Method::POST, &uri, &headers, body)
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
    match resolve_write_target(&state, &slug, &path) {
        Ok(Some((registry_slug, tail))) => {
            crate::facade::put_machine_path(&state, &registry_slug, &tail, &headers, body).await
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
    match resolve_write_target(&state, &slug, &path) {
        Ok(Some((registry_slug, tail))) => {
            crate::facade::head_machine_path(&state, &registry_slug, &tail, &headers).await
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
fn resolve_write_target(
    state: &AppState,
    slug: &str,
    path: &str,
) -> Result<Option<(String, String)>, anyhow::Error> {
    if state.db.registry_by_slug(slug)?.is_some() {
        return Ok(Some((slug.to_string(), path.to_string())));
    }
    let full = format!("{slug}/{path}");
    let decoded = percent_decode(&full);
    match resolve_by_prefix(state, decoded.trim_end_matches('/'))? {
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
    match state.db.registry_surface_root(registry.id) {
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
/// `path` from its upstream, verifies it (content-addressed objects/NARs by
/// hash; pointers fetched live and not frozen), persists content-addressed
/// payloads into the binding `root`, and serves the bytes with the path's
/// machine cache-control. Returns `None` when the registry is not a
/// pull-through mirror, the path is not a machine path, or the upstream lacks
/// it — letting the caller fall back to its `404`. Upstream errors map to
/// `502 Bad Gateway` so the proxy never hangs or 500s on an upstream fault.
async fn pull_through_machine_path(
    state: &AppState,
    registry: &RegistryRecord,
    root: &std::path::Path,
    path: &str,
) -> Option<Response> {
    if !compat::is_machine_path(path) {
        return None;
    }
    let source = match state.db.mirror_source(registry.id) {
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
    let fetch = match crate::fetch::fetch_for_url(&source.upstream_url) {
        Ok(fetch) => fetch,
        Err(err) => return Some(internal(err)),
    };
    match crate::mirror::fetch_through(fetch.as_ref(), root, path).await {
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
            if let Some(response) =
                crate::console::dispatch_nested(&state, &method, &uri, &headers, body).await
            {
                return response;
            }
            resolve_nested(&state, &uri, &headers, Instant::now()).await
        }
        _ => resolve_nested(&state, &uri, &headers, Instant::now()).await,
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
    let target = match resolve_by_prefix(state, decoded.trim_end_matches('/')) {
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
        return match state.db.registry_by_slug(slug) {
            Ok(Some(registry)) => {
                if let Err(deny) = authorize_registry_read(state, &registry, headers) {
                    return *deny;
                }
                render_page(state, &registry, page, headers, started).await
            }
            Ok(None) => StatusCode::NOT_FOUND.into_response(),
            Err(err) => internal(err),
        };
    }

    // No `/-/`: either a registry home (exact slug, trailing slash trimmed)
    // or a machine path (slug + remainder). Resolve by longest slug prefix.
    let trimmed = decoded.trim_end_matches('/');
    match resolve_by_prefix(state, trimmed) {
        Ok(Some((registry, tail))) => {
            if let Err(deny) = authorize_registry_read(state, &registry, headers) {
                return *deny;
            }
            if tail.is_empty() {
                render_page(state, &registry, PageKind::Home, headers, started).await
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
pub(crate) fn resolve_by_prefix(
    state: &AppState,
    path: &str,
) -> Result<Option<(RegistryRecord, String)>, anyhow::Error> {
    let mut candidate = path;
    loop {
        if let Some(registry) = state.db.registry_by_slug(candidate)? {
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
async fn render_page(
    state: &AppState,
    registry: &RegistryRecord,
    page: PageKind,
    headers: &HeaderMap,
    started: Instant,
) -> Response {
    let status = match state.db.index_status(registry.id) {
        Ok(status) => status,
        Err(err) => return internal(err),
    };
    let result = (|| {
        Ok::<_, anyhow::Error>(match &page {
            PageKind::Home => Some(render_home(
                state,
                registry,
                status.as_ref(),
                headers,
                started,
            )?),
            PageKind::Packages => {
                let all = state.db.list_packages(registry.id)?;
                let total = all.len();
                Some(pages::package_index(
                    registry,
                    status.as_ref(),
                    &all,
                    None,
                    pages::PackageSort::Name,
                    None,
                    1,
                    total,
                    total,
                    started,
                ))
            }
            PageKind::Package(name) => match state.db.package_detail(registry.id, name)? {
                Some(detail) => {
                    let closure = resolve_package_closure(&state.db, registry.id, name, &detail)?;
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
                let channels = state.db.list_channels(registry.id)?;
                Some(pages::channels_index(
                    registry,
                    status.as_ref(),
                    &channels,
                    started,
                ))
            }
            PageKind::Channel(name) => {
                let channels = state.db.list_channels(registry.id)?;
                match channels.into_iter().find(|c| &c.name == name) {
                    Some(channel) => {
                        let floor = state.db.channel_floor(registry.id, name)?;
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
                let releases = state.db.list_releases(registry.id)?;
                Some(pages::releases_page(
                    registry,
                    status.as_ref(),
                    &releases,
                    started,
                ))
            }
            PageKind::Health => {
                let mut runs = Vec::new();
                for run in state.db.latest_validation_runs(registry.id)? {
                    let missing = if run.missing > 0 {
                        state.db.validation_missing(run.id)?
                    } else {
                        Vec::new()
                    };
                    let corrupt = if run.missing > 0 {
                        state.db.validation_corrupt(run.id)?
                    } else {
                        Vec::new()
                    };
                    runs.push((run, missing, corrupt));
                }
                let stack = state.db.registry_cache_stack(registry.id)?;
                let probes = state.db.list_cache_probes(registry.id)?;
                let repair_jobs = state
                    .db
                    .list_repair_jobs(registry.id, HEALTH_REPAIR_JOB_LIMIT)?;
                let frontends = state.db.list_frontends(registry.id)?;
                let frontend_probes = state.db.list_frontend_probes(registry.id)?;
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
    })();
    let _ = headers;
    respond_page(result)
}

/// Render a registry home page (shared by flat and nested routes).
fn render_home(
    state: &AppState,
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    headers: &HeaderMap,
    started: Instant,
) -> Result<String, anyhow::Error> {
    let channels = state.db.list_channels(registry.id)?;
    let packages = state.db.list_packages(registry.id)?;
    let caches = state.db.list_caches(registry.id)?;
    let roster = state.db.list_roster(registry.id)?;
    let validations = state.db.latest_validation_runs(registry.id)?;
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
        registry_manage_link(state, registry, headers),
        started,
    ))
}

/// Whether the request's session user may *manage* `registry` — i.e. holds
/// `registry.configure` at its canonical scope — so the registry home renders
/// the "manage this registry" link.
///
/// Returns `false` for an anonymous request or any database error: the link is
/// a pure discoverability affordance, so a lookup failure quietly hides it.
fn registry_manage_link(state: &AppState, registry: &RegistryRecord, headers: &HeaderMap) -> bool {
    let Some(secret) = session_secret_from_cookies(headers) else {
        return false;
    };
    let Ok(Some(session)) = state.db.validate_session(&secret) else {
        return false;
    };
    let Ok(grants) = state
        .db
        .effective_scopes(crate::domain::Principal::user(session.user_id))
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
pub(crate) fn authorize_registry_read(
    state: &AppState,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    let denied = || Box::new(StatusCode::NOT_FOUND.into_response());
    // A registry owned by a soft-deleted org stops serving entirely (RFC-0004
    // offboarding): 404, never disclosing that it once existed.
    if let Some(org_id) = registry.org_id {
        if !matches!(state.db.org_is_active(org_id), Ok(true)) {
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
            if session_is_org_member(state, headers, org_id) {
                Ok(())
            } else {
                Err(denied())
            }
        }
        // Private (or any unknown visibility, fail closed): require Read on
        // the registry scope from a session or a bearer token.
        _ => {
            let scope = Scope::parse(&registry.slug);
            if session_allows_read(state, headers, &scope)
                || bearer_allows_read(state, headers, &scope)
            {
                Ok(())
            } else {
                Err(denied())
            }
        }
    }
}

/// Whether the caller in `headers` may see `registry` at all.
///
/// This is the boolean form of [`authorize_registry_read`], used to filter
/// listings (the instance home and its `?q=` search) so that internal and
/// private registries never leak to callers who could not open their pages.
/// It applies the same access matrix:
///
/// - **public** (and every unowned phase-1 registry) is visible to anyone;
/// - **internal** is visible only to a session member of the owning org;
/// - **private** (and any unknown visibility, failing closed) is visible only
///   when a session or bearer token grants `Read` at the registry scope.
///
/// Keeping the filter in terms of the same primitives as
/// [`authorize_registry_read`] guarantees a registry shown in a listing is one
/// the caller can actually open, and one hidden from the listing 404s on its
/// page — preserving the non-disclosure rule end to end.
pub(crate) fn can_read_registry(
    state: &AppState,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> bool {
    authorize_registry_read(state, registry, headers).is_ok()
}

/// Whether the request's session user holds any membership covering `org_id`.
fn session_is_org_member(state: &AppState, headers: &HeaderMap, org_id: i64) -> bool {
    let Some(org) = state.db.org_by_id(org_id).ok().flatten() else {
        return false;
    };
    let scope = Scope::parse(&org.slug);
    session_allows_read(state, headers, &scope)
}

/// Whether the request's session user may `Read` at `scope` under their
/// current memberships.
fn session_allows_read(state: &AppState, headers: &HeaderMap, scope: &Scope) -> bool {
    let Some(secret) = session_secret_from_cookies(headers) else {
        return false;
    };
    let Ok(Some(session)) = state.db.validate_session(&secret) else {
        return false;
    };
    crate::auth::extract::session_allows(&state.db, &session, Permission::Read, scope)
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
pub(crate) fn session_secret_from_cookies(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{}=", crate::auth::session::COOKIE_NAME);
    cookies
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(&prefix).map(str::to_string))
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
