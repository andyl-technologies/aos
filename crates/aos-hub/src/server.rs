//! Native Hub control-plane and typed delivery router.
//!
//! The router combines the shared Connect-JSON API and Web console with native
//! health, metrics, authentication, and storage adapters. Registry and cache
//! bytes are never selected from URL slugs here: the shared delivery dispatcher
//! resolves an enabled domain/IP route and rewrites it to the typed internal
//! delivery handler. Native and Worker deployments therefore apply the same
//! route, authorization, placement, range, and response-header contracts.
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;

/// Maximum inbound request-body size for the shared RPC surface (8 MiB).
///
/// Connect requests carry small JSON bodies; capping them well below the
/// process's memory budget keeps a hostile or buggy client from streaming an
/// unbounded body into a handler that buffers it. The value is owned by the
/// shared router so native and Worker enforce the same threshold.
pub const RPC_MAX_BODY_BYTES: usize = aos_hub_core::connect::CONNECT_REQUEST_BODY_LIMIT_BYTES;

use crate::auth::extract::AuthState;
use crate::db::Database;
use crate::domain::{Permission, Principal, Scope};

/// Lifetime, in seconds, of a hub access token minted at `/oauth2/token`
/// (1 hour).
///
/// Kept in parity with the Worker
/// (`aos_hub_core::connect`'s `ACCESS_TOKEN_TTL_SECS`): an hour covers a bulk
/// publish while keeping the bearer short-lived; longer-running clients
/// re-exchange the provisioning token rather than relying on a long TTL.
const ACCESS_TOKEN_TTL_SECS: i64 = 3600;

/// Shared state for all handlers.
pub struct AppState {
    /// The hub database.
    pub db: Arc<Database>,
    /// The externally reachable base URL, used in setup snippets.
    pub external_url: String,
    /// Authentication state: JWT keys and the access-token TTL, shared with
    /// the `/oauth2/token` exchange and the mutating ConnectRPC services.
    pub auth: Arc<AuthState>,
    /// Process-local leases serializing retained publication operations.
    pub leases: Arc<aos_hub_core::lease::InMemoryLease>,
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
    /// Provider-backed immutable secret versions for storage and webhooks.
    pub secret_versions: Arc<dyn aos_hub_core::secret_version::SecretVersionResolver>,
    /// Hardened HTTP client for hub-originated OIDC requests (token exchange,
    /// JWKS fetch), with the same timeouts as the surface fetcher.
    pub http: reqwest::Client,
    /// Hub-private immutable signed-image storage (native deployments only).
    pub image_snapshots: Option<Arc<crate::image_snapshot::ImageSnapshotStore>>,
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
    /// Verifier for short-lived assertions from an explicitly configured TLS,
    /// VPN, or layer-7 ingress adapter.
    pub delivery_attestation_verifier:
        Option<Arc<aos_hub_core::delivery_attestation::DeliveryAttestationVerifier>>,
    /// Runtime-owned signer material for the domain-probe well-known route.
    pub domain_probe_terminator:
        Option<Arc<dyn aos_hub_core::topology_probe::DomainProbeTerminatorProvider>>,
    /// Active and retained privacy keys for permanent route URL reservations.
    pub route_reservation_keyring: Option<Arc<dyn aos_hub_core::service::RouteReservationKeyring>>,
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
            leases: Arc::new(aos_hub_core::lease::InMemoryLease::new()),
            mailer: Arc::new(crate::auth::magic::LogMailer),
            dev: false,
            // A deterministic placeholder sealer for dev/tests; production
            // supplies a real one via the struct literal.
            sealer: crate::auth::oidc::dev_sealer(),
            secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
            http: crate::fetch::hardened_client().await,
            image_snapshots: None,
            ratelimit,
            trusted_proxy: false,
            delivery_attestation_verifier: None,
            domain_probe_terminator: None,
            route_reservation_keyring: None,
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
        // The registry must exist and have a fully reconciled write authority.
        let Some(registry) = self.db.registry_by_slug(slug).await? else {
            return Ok(None);
        };
        if self
            .db
            .reconciled_surface_writer(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
            .await
            .is_err()
        {
            return Ok(None);
        }
        // Mint an internal bearer JWT granting publish on the registry scope.
        // The facade authorizes on the JWT's own claims, so a synthetic
        // system-owned TokenAuth suffices.
        let auth = crate::db::TokenAuth {
            token_id: "hub-repair".to_string(),
            owner: Principal::service_account(0),
            scope: Scope::parse(&self.db.registry_authorization_scope(registry.id).await?),
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

/// Builds the native Hub control-plane and typed delivery router.
///
/// Connect-JSON methods and the shared console own the control URL space.
/// Public registry and cache bytes are admitted only by the outer typed
/// delivery-route dispatcher, which rewrites a selected endpoint to the
/// internal delivery handler shared with the Worker runtime.
pub async fn router(state: Arc<AppState>) -> Router {
    // The shared Connect-JSON RPC service, built over the hub's database, signing
    // keys, and base URL (the same fields the old per-hub service held), with the
    // in-process limiter adapted to the core `RateLimiter` port and the native
    // surface provider (filesystem/HTTP fetchers chosen per a registry's storage
    // binding).
    let mut rpc_service = aos_hub_core::service::RpcService::new(
        Arc::clone(&state.db),
        state.auth.jwt_keys.clone(),
        state.external_url.clone(),
        Arc::clone(&state.ratelimit) as Arc<dyn aos_hub_core::ratelimit::RateLimiter>,
        Arc::new(
            crate::coreports::HubSurfaceProvider::new(
                Arc::clone(&state.db),
                state.http.clone(),
                state.image_snapshots.clone(),
            )
            .with_credentials(Arc::clone(&state.secret_versions)),
        ),
        Arc::new(
            crate::coreports::HubSurfaceWriteProvider::new(
                Arc::clone(&state.db),
                state.http.clone(),
            )
            .with_credentials(Arc::clone(&state.secret_versions)),
        ),
        // Publication pointer flips share one in-process lease domain.
        Arc::clone(&state.leases) as Arc<dyn aos_hub_core::lease::PublishLease>,
        Arc::new(
            crate::coreports::HubReindexer::new(
                Arc::clone(&state.db),
                state.image_snapshots.clone(),
            )
            .with_surface_provider(Arc::new(
                crate::coreports::HubSurfaceProvider::new(
                    Arc::clone(&state.db),
                    state.http.clone(),
                    state.image_snapshots.clone(),
                )
                .with_credentials(Arc::clone(&state.secret_versions))
                .for_image_indexing(),
            )),
        ),
        Arc::new(
            aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(Arc::clone(
                &state.db,
            )),
        ),
        Some(Arc::clone(&state.sealer)),
    )
    .with_secret_versions(Arc::clone(&state.secret_versions))
    .with_origin_fetch(Arc::new(crate::coreports::ReqwestOriginFetch::new(
        state.http.clone(),
    )));
    if let Some(provider) = &state.domain_probe_terminator {
        rpc_service = rpc_service.with_domain_probe_terminator(Arc::clone(provider));
    }
    let rpc_service = Arc::new(rpc_service);
    // The shared router owns `/aos.hub.v1.*` and browse routes and carries its
    // own `Arc<RpcService>` state. It has no resource-slug delivery wildcard.
    // Kept for the outermost domain-routing layer below (it captures the service
    // directly, independent of the AppState-typed router's state).
    let dispatch_service = Arc::clone(&rpc_service);
    let rpc_router = aos_hub_core::connect::rpc_browse_router(rpc_service);

    // The `/oauth2/token` exchange fragment runs on Arc<AuthState>; bind its
    // state up front so it merges into the AppState-typed router below.
    let oauth2 = crate::auth::extract::oauth2_router().with_state(Arc::clone(&state.auth));

    // Public bytes never resolve from a resource slug. The outer delivery-route
    // dispatcher rewrites a matched endpoint to the typed internal delivery
    // handler; this router owns only control-plane routes and console pages.
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route(
            "/oauth2/device_authorization",
            axum::routing::post(device_authorization),
        )
        .fallback(nested_console_route);
    // The shared producer-console router (RFC-0004 Phase 5, console-dedup stage
    // B): the wasm-clean management handlers, built over the hub's database,
    // JWT keys, rate limiter, mailer, sealer, the hardened reqwest `HttpClient`
    // port, and the native surface read/write and reindex ports (over which the
    // shared retained-control services coordinate reviewed topology changes).
    // It carries its own `ConsoleDeps` state, so — like `rpc_router` — it is
    // merged after `with_state` below. Nested-canonical registry console pages
    // (slugs with slashes, which the flat `/{slug}/-/…` routes can't capture)
    // are served by the same shared dispatcher from the catch-all — see
    // [`console_deps`] and `dispatch_nested` — so there is a single console
    // routing table for both flat and nested slugs.
    let console_deps = console_deps(&state);
    // Seed the editable site chrome (title/banner/footer) from the database at
    // startup so the masthead reflects persisted branding; a branding save
    // refreshes it live via `set_site_chrome`.
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
    // Kept for the outermost client-IP injection layer below.
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
        .with_state(Arc::clone(&state))
        // The shared Connect-JSON router carries its own `Arc<RpcService>`
        // state, so it is merged after `with_state`.
        .merge(rpc_router)
        // The shared producer-console router carries its own `ConsoleDeps`
        // state, so — like `rpc_router` — it is merged after `with_state`. Its
        // static console paths are wrapped by the same security layers.
        .merge(console_router)
        // Bound every control-plane request. Large object transfer uses typed
        // placement write tickets and backend upload URLs, not this router.
        .layer(DefaultBodyLimit::max(RPC_MAX_BODY_BYTES))
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
    // Typed domain/IP endpoints select the most-specific delivery route before
    // any internal handler matches. Outermost so it runs first on the way in.
    aos_hub_core::connect::with_delivery_route_dispatch(
        app,
        dispatch_service,
        state.delivery_attestation_verifier.clone(),
    )
}

/// Resolve the current session and run the request with the user's email in
/// a task-local (read by the page renderer's masthead).
async fn resolve_session(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let email = match aos_hub_core::web::session::session_secret_from_headers(request.headers()) {
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
    /// Requested stable scope identity (defaults to the instance root when omitted).
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
    let surface: Arc<dyn aos_hub_core::fetch::SurfaceProvider> = Arc::new(
        crate::coreports::HubSurfaceProvider::new(
            Arc::clone(&state.db),
            state.http.clone(),
            state.image_snapshots.clone(),
        )
        .with_credentials(Arc::clone(&state.secret_versions)),
    );
    let surface_write: Arc<dyn aos_hub_core::surface_write::SurfaceWriteProvider> = Arc::new(
        crate::coreports::HubSurfaceWriteProvider::new(Arc::clone(&state.db), state.http.clone())
            .with_credentials(Arc::clone(&state.secret_versions)),
    );
    let reindexer: Arc<dyn aos_hub_core::reindex::Reindexer> = Arc::new(
        crate::coreports::HubReindexer::new(Arc::clone(&state.db), state.image_snapshots.clone())
            .with_surface_provider(Arc::new(
                crate::coreports::HubSurfaceProvider::new(
                    Arc::clone(&state.db),
                    state.http.clone(),
                    state.image_snapshots.clone(),
                )
                .with_credentials(Arc::clone(&state.secret_versions))
                .for_image_indexing(),
            )),
    );
    let topology: Arc<dyn aos_hub_core::web::console::TopologyConsole> = Arc::new(
        aos_hub_core::service::RpcService::new(
            Arc::clone(&state.db),
            state.auth.jwt_keys.clone(),
            state.external_url.clone(),
            Arc::clone(&state.ratelimit) as Arc<dyn aos_hub_core::ratelimit::RateLimiter>,
            Arc::clone(&surface),
            Arc::clone(&surface_write),
            Arc::clone(&state.leases) as Arc<dyn aos_hub_core::lease::PublishLease>,
            Arc::clone(&reindexer),
            Arc::new(
                aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(Arc::clone(
                    &state.db,
                )),
            ),
            Some(Arc::clone(&state.sealer)),
        )
        .with_secret_versions(Arc::clone(&state.secret_versions)),
    );
    aos_hub_core::web::console::ConsoleDeps {
        db: Arc::clone(&state.db),
        jwt_keys: state.auth.jwt_keys.clone(),
        external_url: state.external_url.clone(),
        dev: state.dev,
        ratelimit: Arc::clone(&state.ratelimit) as Arc<dyn aos_hub_core::ratelimit::RateLimiter>,
        mailer: Arc::clone(&state.mailer),
        sealer: Arc::clone(&state.sealer),
        http: Arc::new(crate::coreports::HubHttpClient::new(state.http.clone())),
        surface,
        surface_write,
        reindexer,
        default_storage_location: None,
        // The native hub's in-process database is already colocated and fast, so
        // it runs without a KV cache; token-revocation is immediate via the DB.
        kv: None,
        topology,
    }
}

/// Builds native console dependencies for cross-shell request-contract tests.
///
/// This narrow adapter is compiled only with the non-default `test-support`
/// feature. Production hub and Worker builds therefore expose no constructor
/// whose sole purpose is a foreign crate's test harness.
#[cfg(feature = "test-support")]
#[must_use]
pub fn console_deps_for_worker_test(
    state: &Arc<AppState>,
) -> aos_hub_core::web::console::ConsoleDeps {
    console_deps(state)
}

/// Dispatches nested project and registry console paths.
///
/// Requests outside the shared console manifest are not interpreted as
/// resource-slug delivery paths; they remain a plain `404`.
async fn nested_console_route(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    aos_hub_core::web::console::dispatch_nested(console_deps(&state), method, uri, headers, body)
        .await
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}
