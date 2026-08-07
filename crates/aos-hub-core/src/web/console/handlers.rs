//! The shared producer-console request handlers (RFC-0004 Phase 5, stage B).
//!
//! These are the transport- and runtime-neutral `axum` handlers behind the
//! cookie-authenticated producer console: the account profile, passkey
//! management, the org/project dashboards, and the per-registry management
//! pages (tokens, channels, keys, publish history, delivery routes, cache
//! placements, signing keys, webhooks, and SSO). The page *rendering* lives in
//! [`console_render`](crate::web::console_render); this module is the request
//! edge — [`Session`] extraction, IAM gating, CSRF enforcement on every `POST`,
//! and the plain form/redirect flows that keep the console no-JS.
//!
//! Every handler carries a [`ConsoleDeps`] as its `axum` `State` and reaches
//! each platform capability through a port (see [`super::ports`]), so the module
//! compiles to `wasm32-unknown-unknown` and the native hub and the Cloudflare
//! Worker mount the same [`console_router`](super::console_router).
//!
//! The pre-auth rate-limited paths ([`login_form`], [`login_submit`],
//! [`login_password`], [`passkey_login_begin`], and the device-approval
//! [`activate_form`]/[`activate_submit`] surface) live here too: instead of the
//! native `ConnectInfo` peer socket and a reverse-proxy trust flag, they read the
//! connecting client's IP from the runtime-neutral [`CLIENT_IP_HEADER`] each
//! shell stamps on ingress (RFC-0004 Phase 5, console-dedup stages D and E). The
//! per-org OIDC flow ([`login_sso`], [`oidc_start`], [`oidc_callback`]) lives
//! here too (stage F): its token exchange and JWKS fetch go through the
//! [`HttpClient`](super::ports::HttpClient) port, so it needs no native client.
//! Git-backed configuration and change-request flows use the shared surface
//! read/write ports too; neither runtime carries a private console handler set.
//!
//! # CSRF
//!
//! Every mutating handler here is reached with an ambient session cookie, so it
//! is CSRF-able. Each form embeds a per-session synchronizer token
//! ([`mint_csrf_token`](crate::web::csrf::mint_csrf_token)); the handler verifies
//! it ([`check_csrf`]) and answers `403` on a bad or missing token.
//!
//! # Authorization
//!
//! Page gating uses the session user's *current* effective grants
//! ([`Database::effective_scopes`](crate::db::Database::effective_scopes))
//! through [`iam::allow`](crate::domain::iam::allow). An unauthorized read of a
//! private resource returns `404` (existence is never disclosed); a forbidden
//! mutation returns `403`.

use crate::clock::Instant;

use std::sync::Arc;

use axum::extract::{Form, Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use base64::Engine as _;

use crate::auth::session::{set_cookie_header, ABSOLUTE_LIFETIME_SECS, COOKIE_NAME};
use crate::config;
use crate::db::{Database, OrgRecord, RegistryRecord, SessionAuth as DbSession};
use crate::domain::{iam, Permission, Principal, Role, Scope};
use crate::web::console::ia::{
    CachePage, NavigationPermissions, OrgPage, RegistryPage, BINDING_PAGES, CACHE_PAGES, ORG_PAGES,
    REGISTRY_PAGES,
};
use crate::web::console::ports::{
    ConsoleDeps, ConsumerGrantAction, PlacementCreateSpec, PlacementLifecycleAction,
    PlacementPlanOperation, PlacementUpdateSpec, StorageCredentialAction, TopologySurface,
};
use crate::web::console_render as console;
use crate::web::csrf::{connect_or_csrf_ok, mint_csrf_token, verify_csrf_token};
use crate::web::session::resolve_session_from_headers;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

// -- shared helpers ---------------------------------------------------------

/// A per-request start instant, captured when the handler's arguments are
/// extracted (before its body runs) so the "rendered … ms" footer reflects
/// real handler + DB time rather than ~0.
pub(crate) struct RequestStart(pub Instant);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RequestStart {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(RequestStart(Instant::now()))
    }
}

/// A `500 Internal Server Error` response that logs the underlying cause.
///
/// The console's catch-all for an unexpected database or capability failure:
/// the cause is traced server-side and the client sees only a generic message.
pub(crate) fn internal(err: anyhow::Error) -> Response {
    tracing::error!(error = %format!("{err:#}"), "request failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// A resolved session: the secret (for CSRF minting), the user row, and the
/// user's email.
///
/// Built by [`require_session`] from the request's `__Host-aos_session` cookie.
pub(crate) struct Session {
    secret: String,
    auth: DbSession,
    email: String,
}

/// Load and validate the request's session, or return a redirect to `/login`.
///
/// The producer console is human-only; an anonymous or invalid cookie is
/// bounced to the login page rather than `401`'d, so a logged-out click lands
/// somewhere useful. Delegates cookie parsing and validation to the
/// runtime-neutral [`resolve_session_from_headers`].
///
/// # Errors
///
/// Returns the boxed redirect/`500` response in the `Err` arm; `Ok` carries the
/// resolved [`Session`].
pub(crate) async fn require_session(
    deps: &ConsoleDeps,
    headers: &HeaderMap,
) -> Result<Session, Box<Response>> {
    require_session_with_return(deps, headers, None).await
}

/// Loads a session and preserves one validated destination through login.
async fn require_session_with_return(
    deps: &ConsoleDeps,
    headers: &HeaderMap,
    return_to: Option<&str>,
) -> Result<Session, Box<Response>> {
    let resolved = match resolve_session_from_headers(&deps.db, headers).await {
        Ok(Some(resolved)) => resolved,
        Ok(None) => {
            let location = safe_return_path(return_to).map_or_else(
                || "/login".to_string(),
                |path| format!("/login?next={}", urlencode(path)),
            );
            return Err(Box::new(Redirect::to(&location).into_response()));
        }
        Err(err) => return Err(Box::new(internal(err))),
    };
    Ok(Session {
        secret: resolved.secret,
        auth: resolved.auth,
        email: resolved.email,
    })
}

impl Session {
    /// This session user's principal.
    fn principal(&self) -> Principal {
        Principal::user(self.auth.user_id)
    }

    /// The session's current effective grants.
    async fn grants(&self, db: &Database) -> anyhow::Result<Vec<(Scope, Role)>> {
        db.effective_scopes(self.principal()).await
    }

    /// Whether this session may `perm` at `scope` under its current grants.
    async fn allows(&self, db: &Database, perm: Permission, scope: &Scope) -> bool {
        let (Ok(grants), Ok(Some(context))) = (
            self.grants(db).await,
            db.authorization_context(scope.as_str()).await,
        ) else {
            return false;
        };
        iam::allow(&grants, perm, &context)
    }

    /// The CSRF synchronizer token bound to this session.
    fn csrf(&self) -> String {
        mint_csrf_token(&self.secret)
    }

    /// Mints a short-lived internal bearer for the shared topology service.
    ///
    /// The token carries the broad owner verb set, but service authorization
    /// still intersects it with this principal's live database memberships on
    /// every call. The Web layer therefore cannot retain authority after a role
    /// revocation while still using the exact API/CLI control-plane path.
    fn topology_bearer(&self, deps: &ConsoleDeps, scope: Scope) -> anyhow::Result<String> {
        let ttl = self
            .auth
            .expires_at
            .saturating_sub(crate::clock::now_unix_secs())
            .clamp(1, 300);
        let token = deps.jwt_keys.mint(
            &crate::db::TokenAuth {
                token_id: format!("console-session-{}", self.auth.user_id),
                owner: self.principal(),
                scope,
                permissions: iam::role_grants(Role::Owner).to_vec(),
            },
            ttl,
        )?;
        Ok(format!("Bearer {token}"))
    }
}

/// Lifetime of a bearer minted from an authenticated browser session.
pub(crate) const BROWSER_ACCESS_TOKEN_TTL_SECS: i64 = 300;

#[derive(serde::Serialize)]
struct SessionTokenPrincipal {
    kind: &'static str,
    id: i64,
    email: String,
}

#[derive(serde::Serialize)]
struct SessionTokenGrant {
    scope: String,
    role: String,
}

#[derive(serde::Serialize)]
struct SessionTokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    principal: SessionTokenPrincipal,
    grants: Vec<SessionTokenGrant>,
}

/// Exchanges an authenticated browser session for a short-lived API bearer.
///
/// The ambient session cookie is accepted only with an exact same-origin
/// `Origin` header and the session-bound `x-aos-csrf` proof. The response is
/// explicitly non-cacheable, and callers must retain the bearer only in
/// memory.
pub(crate) async fn session_token(deps: ConsoleDeps, headers: HeaderMap) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => {
            let mut response = *response;
            if response.status().is_redirection() {
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                response.headers_mut().remove(header::LOCATION);
            }
            return response;
        }
    };
    if !request_has_exact_origin(&headers, &deps.external_url) {
        return (StatusCode::FORBIDDEN, "invalid request origin").into_response();
    }
    let csrf = headers
        .get("x-aos-csrf")
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|token| verify_csrf_token(&session.secret, token)) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }

    let grants = match session.grants(&deps.db).await {
        Ok(grants) => grants,
        Err(error) => return internal(error),
    };
    let auth = crate::db::TokenAuth {
        token_id: format!("browser-session-{}", session.auth.user_id),
        owner: session.principal(),
        scope: Scope::root(),
        permissions: iam::role_grants(Role::Owner).to_vec(),
    };
    let access_token = match deps.jwt_keys.mint(&auth, BROWSER_ACCESS_TOKEN_TTL_SECS) {
        Ok(token) => token,
        Err(error) => return internal(error),
    };
    let body = SessionTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: BROWSER_ACCESS_TOKEN_TTL_SECS,
        principal: SessionTokenPrincipal {
            kind: "user",
            id: session.auth.user_id,
            email: session.email,
        },
        grants: grants
            .into_iter()
            .map(|(scope, role)| SessionTokenGrant {
                scope: scope.as_str().to_string(),
                role: role.as_str().to_string(),
            })
            .collect(),
    };
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

fn request_has_exact_origin(headers: &HeaderMap, external_url: &str) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let (Ok(origin), Ok(external)) = (url::Url::parse(origin), url::Url::parse(external_url))
    else {
        return false;
    };
    origin.scheme() == external.scheme()
        && origin.host_str() == external.host_str()
        && origin.port_or_known_default() == external.port_or_known_default()
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none()
}

// -- OAuth device and refresh grants ---------------------------------------

/// Public OAuth client identifier used by the AOS CLI.
const CLI_CLIENT_ID: &str = "aos-cli";
/// RFC 8628 device-code grant type.
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Explicit grant for exchanging an administrator-issued provisioning token.
const PROVISIONING_TOKEN_GRANT: &str = "urn:aos:params:oauth:grant-type:provisioning-token";
/// Lifetime of a CLI access JWT.
const CLI_ACCESS_TOKEN_TTL_SECS: i64 = 3600;

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct DeviceAuthorizationForm {
    client_id: String,
    scope: Option<String>,
    permission: Option<String>,
}

#[derive(serde::Serialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
}

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct OAuthTokenForm {
    #[serde(default)]
    grant_type: String,
    client_id: Option<String>,
    device_code: Option<String>,
    refresh_token: Option<String>,
}

#[derive(serde::Serialize)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token_expires_in: Option<i64>,
    capabilities: [&'static str; 2],
}

#[derive(serde::Serialize)]
struct OAuthErrorResponse {
    error: &'static str,
    error_description: &'static str,
}

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct OAuthRevokeForm {
    token: String,
    token_type_hint: Option<String>,
    client_id: Option<String>,
}

fn oauth_response(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn oauth_error(status: StatusCode, error: &'static str, description: &'static str) -> Response {
    oauth_response((
        status,
        Json(OAuthErrorResponse {
            error,
            error_description: description,
        }),
    ))
}

async fn oauth_rate_limit(
    deps: &ConsoleDeps,
    headers: &HeaderMap,
    class: crate::ratelimit::RateClass,
) -> Option<Response> {
    let ip = resolved_client_ip(headers);
    match deps
        .ratelimit
        .check(class, &ip, crate::clock::now_unix_secs())
        .await
    {
        crate::ratelimit::RateDecision::Allowed => None,
        crate::ratelimit::RateDecision::Limited { retry_after } => {
            let mut response = oauth_error(
                StatusCode::TOO_MANY_REQUESTS,
                "slow_down",
                "request rate limit exceeded",
            );
            if let Ok(value) = HeaderValue::from_str(&retry_after.max(1).to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            Some(response)
        }
    }
}

/// Starts an RFC 8628 authorization grant for the public AOS CLI client.
pub(crate) async fn device_authorization(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<DeviceAuthorizationForm>,
) -> Response {
    if form.client_id != CLI_CLIENT_ID {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id must identify the AOS CLI",
        );
    }
    if let Some(response) = oauth_rate_limit(
        &deps,
        &headers,
        crate::ratelimit::RateClass::DeviceAuthorization,
    )
    .await
    {
        return response;
    }

    let scope = form
        .scope
        .unwrap_or_else(|| Scope::root().as_str().to_string());
    if !Scope::is_canonical(&scope) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope must be a canonical stable scope identity",
        );
    }
    let permission_names = form.permission.as_deref().unwrap_or_default();
    let permissions = if permission_names.is_empty() {
        iam::role_grants(Role::Owner).to_vec()
    } else {
        let parsed = permission_names
            .split_ascii_whitespace()
            .map(crate::auth::permission_from_str)
            .collect::<Option<Vec<_>>>();
        let Some(parsed) = parsed else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "permission contains an unknown verb",
            );
        };
        parsed
    };

    match deps
        .db
        .start_device_authorization(&scope, &permissions)
        .await
    {
        Ok((device_code, user_code, expires_in)) => {
            let verification_uri = format!("{}/activate", deps.external_url.trim_end_matches('/'));
            oauth_response(Json(DeviceAuthorizationResponse {
                device_code,
                verification_uri_complete: format!("{verification_uri}?user_code={user_code}"),
                user_code,
                verification_uri,
                expires_in,
                interval: 5,
            }))
        }
        Err(error) => oauth_response(internal(error)),
    }
}

/// Exchanges an explicit device, refresh, or provisioning grant for a JWT.
pub(crate) async fn oauth_token(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<OAuthTokenForm>,
) -> Response {
    if let Some(response) =
        oauth_rate_limit(&deps, &headers, crate::ratelimit::RateClass::TokenExchange).await
    {
        return response;
    }

    match form.grant_type.as_str() {
        DEVICE_CODE_GRANT => {
            if form.client_id.as_deref() != Some(CLI_CLIENT_ID) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_client",
                    "client_id must identify the AOS CLI",
                );
            }
            let Some(device_code) = form.device_code.as_deref() else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "device_code is required",
                );
            };
            match deps.db.poll_device(device_code).await {
                Ok(crate::db::DevicePollResult::Pending) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "authorization_pending",
                    "the user has not completed authorization",
                ),
                Ok(crate::db::DevicePollResult::SlowDown) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "slow_down",
                    "poll no more often than the advertised interval",
                ),
                Ok(crate::db::DevicePollResult::Denied) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "access_denied",
                    "the user denied authorization",
                ),
                Ok(crate::db::DevicePollResult::Expired) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "expired_token",
                    "the device code is expired or already consumed",
                ),
                Ok(crate::db::DevicePollResult::Approved(grant)) => {
                    oauth_access_grant(&deps, grant, true)
                }
                Err(error) => oauth_response(internal(error)),
            }
        }
        "refresh_token" => {
            if form.client_id.as_deref() != Some(CLI_CLIENT_ID) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_client",
                    "client_id must identify the AOS CLI",
                );
            }
            let Some(refresh_token) = form.refresh_token.as_deref() else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                );
            };
            match deps.db.rotate_refresh_token(refresh_token).await {
                Ok(crate::db::RefreshTokenResult::Rotated(grant)) => {
                    oauth_access_grant(&deps, grant, true)
                }
                Ok(crate::db::RefreshTokenResult::Invalid)
                | Ok(crate::db::RefreshTokenResult::Reused) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "the refresh credential is invalid",
                ),
                Err(error) => oauth_response(internal(error)),
            }
        }
        PROVISIONING_TOKEN_GRANT => {
            let secret = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "));
            let Some(secret) = secret else {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "a provisioning bearer is required",
                );
            };
            match deps.db.validate_token(secret).await {
                Ok(Some(auth)) => oauth_access_token(&deps, &auth, None, None),
                Ok(None) => oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_grant",
                    "the provisioning credential is invalid",
                ),
                Err(error) => oauth_response(internal(error)),
            }
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type is not supported",
        ),
    }
}

fn oauth_access_grant(
    deps: &ConsoleDeps,
    grant: crate::db::DeviceTokenGrant,
    include_refresh: bool,
) -> Response {
    let refresh_token = include_refresh.then_some(grant.refresh_token);
    let refresh_expires_in = include_refresh.then_some(grant.refresh_expires_in);
    oauth_access_token(deps, &grant.auth, refresh_token, refresh_expires_in)
}

fn oauth_access_token(
    deps: &ConsoleDeps,
    auth: &crate::db::TokenAuth,
    refresh_token: Option<String>,
    refresh_token_expires_in: Option<i64>,
) -> Response {
    match deps.jwt_keys.mint(auth, CLI_ACCESS_TOKEN_TTL_SECS) {
        Ok(access_token) => oauth_response(Json(OAuthTokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: CLI_ACCESS_TOKEN_TTL_SECS,
            refresh_token,
            refresh_token_expires_in,
            capabilities: ["aos.hub.topology.v1", "aos.multipart.v1"],
        })),
        Err(error) => oauth_response(internal(error)),
    }
}

/// Revokes the complete refresh-token family containing the supplied token.
pub(crate) async fn oauth_revoke(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<OAuthRevokeForm>,
) -> Response {
    if form.client_id.as_deref() != Some(CLI_CLIENT_ID)
        || form.token_type_hint.as_deref() != Some("refresh_token")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id and refresh_token token_type_hint are required",
        );
    }
    if let Some(response) =
        oauth_rate_limit(&deps, &headers, crate::ratelimit::RateClass::TokenExchange).await
    {
        return response;
    }
    match deps.db.revoke_refresh_token(&form.token).await {
        Ok(_) => oauth_response(StatusCode::OK),
        Err(error) => oauth_response(internal(error)),
    }
}

/// Resolves the exact settings-page permissions available in `scope` with one
/// grant and authorization-context read.
async fn navigation_permissions(
    db: &Database,
    session: &Session,
    scope: &Scope,
) -> anyhow::Result<NavigationPermissions> {
    let grants = session.grants(db).await?;
    let Some(context) = db.authorization_context(scope.as_str()).await? else {
        return Ok(NavigationPermissions::new());
    };
    Ok(ORG_PAGES
        .iter()
        .map(|page| page.permission)
        .chain(REGISTRY_PAGES.iter().map(|page| page.permission))
        .chain(CACHE_PAGES.iter().map(|page| page.permission))
        .chain(BINDING_PAGES.iter().map(|page| page.permission))
        .filter(|permission| iam::allow(&grants, *permission, &context))
        .collect())
}

async fn grants_allow(
    db: &Database,
    grants: &[(Scope, Role)],
    permission: Permission,
    scope: &Scope,
) -> bool {
    match db.authorization_context(scope.as_str()).await {
        Ok(Some(context)) => iam::allow(grants, permission, &context),
        Ok(None) | Err(_) => false,
    }
}

/// Resolves a human organization slug to its non-reusable authorization
/// identity, returning a deliberately noncanonical scope on lookup failure.
/// The latter makes every caller's ordinary permission check fail closed while
/// preserving its existing 403/404 response policy.
async fn organization_scope(db: &Database, slug: &str) -> Scope {
    db.org_by_slug(slug)
        .await
        .ok()
        .flatten()
        .map(|org| Scope::parse(&org.stable_id))
        .unwrap_or_else(Scope::denied)
}

/// Resolves a registry's display identity to its immutable owner scope and
/// fails closed when the registry or live owner incarnation disappears.
async fn registry_scope(db: &Database, registry: &RegistryRecord) -> Scope {
    db.registry_authorization_scope(registry.id)
        .await
        .ok()
        .filter(|scope| Scope::is_canonical(scope))
        .map(|scope| Scope::parse(&scope))
        .unwrap_or_else(Scope::denied)
}

/// Verify the CSRF token in a submitted form against the session secret.
///
/// The hidden `csrf` form field is copied into the `x-aos-csrf` header shape
/// [`connect_or_csrf_ok`] checks; a mismatch is a `403`.
///
/// # Errors
///
/// Returns a boxed `403` response when the token is missing or wrong.
fn check_csrf(session: &Session, csrf: &str) -> Result<(), Box<Response>> {
    let mut headers = HeaderMap::new();
    if let Ok(value) = csrf.parse() {
        headers.insert("x-aos-csrf", value);
    }
    if connect_or_csrf_ok(&headers, Some(&session.secret)) {
        Ok(())
    } else {
        Err(Box::new(
            (StatusCode::FORBIDDEN, "bad or missing CSRF token").into_response(),
        ))
    }
}

/// Require that the session is **sudo** (recently re-authenticated).
///
/// The most destructive operations (password change, registry/org deletion,
/// credential minting) gate on this. A session that has fallen out of the sudo
/// window is sent to the in-place re-authentication ("confirm your identity")
/// page rather than dead-ending on a bare `403`; `headers` supplies the
/// `Referer` so that page can return the user to where they were.
///
/// # Errors
///
/// Returns the boxed re-authentication page — HTTP `403` (the action is
/// forbidden until the caller re-authenticates) carrying the "confirm your
/// identity" form as its body — when the session is not within the sudo window.
fn require_sudo(session: &Session, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if session.auth.is_sudo(crate::clock::now_unix_secs()) {
        return Ok(());
    }
    let return_to = same_origin_return_to(headers);
    let page = console::reauth_page(
        &session.email,
        &session.csrf(),
        &return_to,
        None,
        crate::clock::Instant::now(),
    );
    Err(Box::new(
        (StatusCode::FORBIDDEN, Html(page)).into_response(),
    ))
}

/// Extract a safe same-origin return path from the request's `Referer`.
///
/// Used by the sudo re-auth flow to send the user back to the page they were on.
/// Only the path-and-query is taken (never the host), so a forged `Referer` can
/// at most return the user to a path on this origin — never an open redirect.
/// Falls back to `/` when there is no usable `Referer`.
fn same_origin_return_to(headers: &HeaderMap) -> String {
    headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(|referer| {
            // A relative path is taken as-is; an absolute URL is reduced to its
            // path+query (dropping scheme/host).
            if let Some(stripped) = referer.strip_prefix('/') {
                Some(format!("/{stripped}"))
            } else {
                url::Url::parse(referer).ok().map(|u| {
                    let mut p = u.path().to_string();
                    if let Some(q) = u.query() {
                        p.push('?');
                        p.push_str(q);
                    }
                    p
                })
            }
        })
        .filter(|p| p.starts_with('/') && !p.starts_with("//"))
        .filter(|p| p != "/-/reauth" && !p.starts_with("/login"))
        .unwrap_or_else(|| "/".to_string())
}

/// `POST /-/reauth` form: the password to confirm identity, and where to return.
#[derive(serde::Deserialize)]
pub(crate) struct ReauthForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    return_to: String,
}

/// `POST /-/reauth` — re-authenticate the current session into the sudo window.
///
/// The in-place "confirm your identity" step backing [`require_sudo`]: it
/// verifies the logged-in user's password, elevates the session into a fresh
/// sudo window via [`Database::elevate_session`](crate::db::Database::elevate_session),
/// and redirects back to the (same-origin) `return_to`. A passwordless account
/// (SSO/magic-link only) is told to re-authenticate through its sign-in provider.
pub(crate) async fn reauth(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<ReauthForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let return_to = {
        let p = form.return_to.trim();
        if p.starts_with('/')
            && !p.starts_with("//")
            && p != "/-/reauth"
            && !p.starts_with("/login")
        {
            p.to_string()
        } else {
            "/".to_string()
        }
    };
    let render_err = |msg: &str| {
        Html(console::reauth_page(
            &session.email,
            &session.csrf(),
            &return_to,
            Some(msg),
            started,
        ))
        .into_response()
    };
    // Verify the password against the session's own user (never a different
    // account, even if the email somehow resolves elsewhere).
    let (user_id, hash) = match deps.db.user_for_password(&session.email).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            return render_err(
                "This account has no password set — re-authenticate with your sign-in provider.",
            );
        }
        Err(err) => return internal(err),
    };
    if user_id != session.auth.user_id
        || !crate::auth::password::verify_password(&form.password, &hash)
    {
        return render_err("Incorrect password.");
    }
    if let Err(err) = deps.db.elevate_session(&session.secret).await {
        return internal(err);
    }
    Redirect::to(&return_to).into_response()
}

/// Authorize an anonymous-or-bearer **read** of `registry`, returning a boxed
/// `404` denial when the read is not permitted.
///
/// Reimplements the hub's `authorize_registry_read` over the shared database
/// and JWT keys so the moved read pages enforce the identical access matrix:
///
/// - a registry owned by a soft-deleted org `404`s entirely;
/// - **public** (and any unowned registry) is always readable;
/// - **internal** requires a session member of the owning org;
/// - **private** (and any unknown visibility, fail-closed) requires `Read` at
///   the registry scope from a session *or* a bearer JWT.
///
/// Unauthorized `internal`/`private` reads return **404, not 403**, so a hidden
/// registry's existence is never disclosed.
///
/// # Errors
///
/// Returns the boxed `404` denial in the `Err` arm when the read is not
/// authorized; `Ok(())` means the caller may proceed.
async fn authorize_registry_read(
    deps: &ConsoleDeps,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    let denied = || Box::new(StatusCode::NOT_FOUND.into_response());
    if let Some(org_id) = registry.org_id {
        if !matches!(deps.db.org_is_active(org_id).await, Ok(true)) {
            return Err(denied());
        }
    }
    match registry.visibility.as_str() {
        "public" => Ok(()),
        "internal" => {
            let Some(org_id) = registry.org_id else {
                return Ok(());
            };
            if session_is_org_member(deps, headers, org_id).await {
                Ok(())
            } else {
                Err(denied())
            }
        }
        _ => {
            let Ok(scope_key) = deps.db.registry_authorization_scope(registry.id).await else {
                return Err(denied());
            };
            let scope = Scope::parse(&scope_key);
            if session_allows_read(deps, headers, &scope).await
                || bearer_allows_read(deps, headers, &scope).await
            {
                Ok(())
            } else {
                Err(denied())
            }
        }
    }
}

/// Whether the request's session user holds any membership covering `org_id`.
async fn session_is_org_member(deps: &ConsoleDeps, headers: &HeaderMap, org_id: i64) -> bool {
    let Some(org) = deps.db.org_by_id(org_id).await.ok().flatten() else {
        return false;
    };
    let scope = Scope::parse(&org.stable_id);
    session_allows_read(deps, headers, &scope).await
}

/// Whether the request's session user may `Read` at `scope` under their current
/// memberships.
async fn session_allows_read(deps: &ConsoleDeps, headers: &HeaderMap, scope: &Scope) -> bool {
    let Some(secret) = crate::web::session::session_secret_from_headers(headers) else {
        return false;
    };
    let Ok(Some(session)) = deps.db.validate_session(&secret).await else {
        return false;
    };
    let Ok(grants) = deps
        .db
        .effective_scopes(Principal::user(session.user_id))
        .await
    else {
        return false;
    };
    let Ok(Some(context)) = deps.db.authorization_context(scope.as_str()).await else {
        return false;
    };
    iam::allow(&grants, Permission::Read, &context)
}

/// Whether a bearer JWT in `headers` grants `Read` at `scope`.
async fn bearer_allows_read(deps: &ConsoleDeps, headers: &HeaderMap, scope: &Scope) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    let Ok(Some(context)) = deps.db.authorization_context(scope.as_str()).await else {
        return false;
    };
    match deps.jwt_keys.verify(token) {
        Ok(claims) => {
            if !iam::token_allows(&claims, Permission::Read, &context) {
                return false;
            }
            let Some(principal) = iam::claims_principal(&claims) else {
                return false;
            };
            match deps.db.effective_scopes(principal).await {
                Ok(grants) => iam::allow(&grants, Permission::Read, &context),
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Percent-encode a string for a query component.
fn urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

/// The request header carrying the deployment-resolved client IP.
///
/// The pre-auth handlers ([`login_submit`], [`login_password`],
/// [`passkey_login_begin`], and the [`activate_form`]/[`activate_submit`]
/// surface) rate-limit on the connecting client's IP, but the connecting peer
/// address and the reverse-proxy trust model are *runtime-specific* (a native
/// `ConnectInfo`
/// socket on the hub, a `cf-connecting-ip` header on the Worker) and so are not
/// available to these wasm-clean handlers. Each shell resolves the trusted IP in
/// its own ingress layer and stamps it onto this header; the handlers read it
/// back through [`resolved_client_ip`].
///
/// # Security invariant
///
/// This header's value is **shell-controlled, not client-controlled**. Each
/// deployment MUST *overwrite* this header on ingress — inserting the
/// shell-resolved value and replacing any inbound value of the same name —
/// *before* the shared console handlers run. If a deployment merely appended (or
/// trusted an inbound value), a client could forge its own IP string and so mint
/// an arbitrary rate-limit bucket, defeating the per-IP abuse bound on the
/// pre-auth login paths.
///
/// An **absent** value (a misconfigured deployment that never stamps the header)
/// is treated as the empty string by [`resolved_client_ip`]: every caller then
/// shares one rate-limit bucket. That fails *safe* for abuse (the bound still
/// applies, just coarsely) rather than failing open.
pub const CLIENT_IP_HEADER: &str = "x-aos-client-ip";

/// The deployment-resolved client IP from the request headers, or `""` when the
/// header is absent.
///
/// Reads the [`CLIENT_IP_HEADER`] the ingress layer stamped. See that constant's
/// documentation for the security invariant: the value is shell-controlled, and
/// an absent value (a misconfiguration) collapses every caller into one shared
/// rate-limit bucket rather than failing open.
pub(crate) fn resolved_client_ip(headers: &HeaderMap) -> String {
    headers
        .get(CLIENT_IP_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

// -- login (email magic link + password) ------------------------------------

/// `GET /login` — the email-first login form, plus the passkey sign-in button.
///
/// Sets a per-request `script-src 'nonce-…'` CSP (via [`passkey_html_response`])
/// so the page's first-party passkey script (driving `navigator.credentials.get`)
/// runs while every other inline script stays blocked.
pub(crate) async fn login_form(
    _deps: ConsoleDeps,
    RequestStart(started): RequestStart,
    Query(query): Query<LoginQuery>,
) -> Response {
    let nonce = crate::auth::webauthn::new_challenge();
    let next = safe_return_path(query.next.as_deref());
    let html = console::login_page(None, Some(&nonce), next, started);
    passkey_html_response(html, &nonce)
}

/// Optional same-origin destination carried through browser authentication.
#[derive(serde::Deserialize, Default)]
pub(crate) struct LoginQuery {
    #[serde(default)]
    next: Option<String>,
}

/// `POST /login` body: the email to send a magic link to.
#[derive(serde::Deserialize)]
pub(crate) struct LoginForm {
    email: String,
    #[serde(default)]
    next: Option<String>,
}

/// `POST /login` — route to SSO or issue a magic link.
///
/// Email-first routing (RFC-0004 "domain capture"): when the typed email's
/// domain is captured by an org with an OIDC IdP, the response depends on the
/// org's `enforce_sso`:
///
/// - **enforced** — redirect straight into the OIDC flow (`/auth/oidc/start`);
///   magic links are not offered.
/// - **not enforced** — show a two-step page offering a "Sign in with SSO"
///   button *and* a magic link, keeping the no-JS floor.
///
/// Otherwise a magic link is issued and the "check your email" page shown. The
/// address is never revealed as known/unknown.
///
/// Rate-limited on both the target email and the source IP (the
/// [`resolved_client_ip`] the ingress layer stamped — see [`CLIENT_IP_HEADER`]).
pub(crate) async fn login_submit(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<LoginForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    let next = safe_return_path(form.next.as_deref());
    if email.is_empty() || !email.contains('@') {
        return Html(console::login_page(
            Some("Enter a valid email address."),
            None,
            next,
            started,
        ))
        .into_response();
    }
    // Rate-limit magic-link issuance on both the target email (the email-bomb
    // victim) and the source IP (the sender) — see [`crate::ratelimit`].
    let now = crate::clock::now_unix_secs();
    let ip = resolved_client_ip(&headers);
    use crate::ratelimit::RateClass;
    for (class, key) in [
        (RateClass::MagicLinkEmail, email.as_str()),
        (RateClass::MagicLinkIp, ip.as_str()),
    ] {
        if let crate::ratelimit::RateDecision::Limited { retry_after } =
            deps.ratelimit.check(class, key, now).await
        {
            return too_many_requests(retry_after);
        }
    }
    // Domain capture: route to the org's IdP when one is configured.
    if let Some((org_slug, enforce_sso)) = sso_target(&deps, &email).await {
        let start = sso_start_path(&org_slug, next);
        if enforce_sso {
            return Redirect::to(&start).into_response();
        }
        return Html(console::login_sso_page(
            &email, &org_slug, &start, next, started,
        ))
        .into_response();
    }
    let secret = match deps.db.create_magic_link(&email).await {
        Ok(secret) => secret,
        Err(err) => return internal(err),
    };
    let mut link = format!(
        "{}/auth/magic?token={secret}",
        deps.external_url.trim_end_matches('/'),
    );
    if let Some(next) = next {
        link.push_str("&next=");
        link.push_str(&urlencode(next));
    }
    // Render with the configured brand so the email reads "Sign in to <brand>"
    // rather than the generic fallback; the transport differs per shell but the
    // copy is shared (see `crate::email`).
    let content = crate::email::magic_link_email(console::brand(), &link);
    if let Err(err) = deps.mailer.send_email(&email, &content).await {
        tracing::warn!(error = %format!("{err:#}"), "magic link delivery failed");
    }
    // In `--dev` mode the mailer only logs, so surface the link on the page so a
    // local operator can follow it (the native hub keyed this off `LogMailer`).
    let dev_link = deps.dev.then_some(link.as_str());
    Html(console::login_sent_page(&email, dev_link, started)).into_response()
}

/// `POST /login/password` body: the email and password to authenticate.
#[derive(serde::Deserialize)]
pub(crate) struct PasswordLoginForm {
    email: String,
    password: String,
    #[serde(default)]
    next: Option<String>,
}

/// `POST /login/password` — authenticate an email + password, sign the user in.
///
/// This is a **pre-auth** endpoint (the caller has no session cookie yet), so it
/// carries no CSRF token — there is no ambient credential to forge against. It
/// *is* rate-limited on both the target email (online password guessing against
/// one account) and the source IP (credential-stuffing sprays), reusing the
/// [`RateClass::PasswordEmail`]/[`RateClass::PasswordIp`] classes keyed on the
/// [`resolved_client_ip`] the ingress layer stamped (see [`CLIENT_IP_HEADER`]).
///
/// On a correct password it creates a sudo-capable session (a fresh password
/// sign-in is a re-authentication, `auth_level 1`), sets the `__Host-` cookie,
/// and redirects to `/`. On *any* failure — unknown email, no password set, or a
/// wrong password — it re-renders `/login` with one generic "invalid email or
/// password" message, never revealing whether the email is registered.
///
/// [`RateClass::PasswordEmail`]: crate::ratelimit::RateClass::PasswordEmail
/// [`RateClass::PasswordIp`]: crate::ratelimit::RateClass::PasswordIp
pub(crate) async fn login_password(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<PasswordLoginForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    let next = safe_return_path(form.next.as_deref());
    // The single generic failure render, used for every rejection path so the
    // endpoint is not an account-existence oracle.
    let invalid = || {
        Html(console::login_page(
            Some("Invalid email or password."),
            None,
            next,
            started,
        ))
        .into_response()
    };
    if email.is_empty() || !email.contains('@') || form.password.is_empty() {
        return invalid();
    }
    // Instance policy: when local password login is disabled, refuse it outright
    // (the instance is SSO/magic-link only). This is a global posture, not
    // account-specific, so a clear message is no account-existence oracle.
    if !password_login_enabled(&deps).await {
        return Html(console::login_page(
            Some("Password login is disabled on this instance. Use SSO or a magic link."),
            None,
            next,
            started,
        ))
        .into_response();
    }
    // Rate-limit on both the target email and the source IP before doing the
    // (deliberately expensive) Argon2 verify, so a spray cannot burn CPU.
    let now = crate::clock::now_unix_secs();
    let ip = resolved_client_ip(&headers);
    use crate::ratelimit::RateClass;
    for (class, key) in [
        (RateClass::PasswordEmail, email.as_str()),
        (RateClass::PasswordIp, ip.as_str()),
    ] {
        if let crate::ratelimit::RateDecision::Limited { retry_after } =
            deps.ratelimit.check(class, key, now).await
        {
            return too_many_requests(retry_after);
        }
    }
    let (user_id, hash) = match deps.db.user_for_password(&email).await {
        Ok(Some(found)) => found,
        // No such user, or no password set. Still spend an Argon2id verify
        // against a fixed dummy hash before failing, so the wall-clock time of
        // this miss matches that of an existing account — otherwise the
        // short-circuit leaks account existence as a timing oracle (M10).
        Ok(None) => {
            crate::auth::password::spend_dummy_verify(&form.password);
            return invalid();
        }
        Err(err) => return internal(err),
    };
    if !crate::auth::password::verify_password(&form.password, &hash) {
        return invalid();
    }
    // Even with a correct password, a user subject to `enforce_sso` must come
    // through the IdP — a local password must not bypass IdP deprovisioning,
    // MFA, or conditional access (H-4). The credential already verified, so the
    // account is known to exist; redirecting to SSO leaks nothing a successful
    // password login would not, and matches the magic-link path's UX. (Reaching
    // here with the password verified means an SSO-enforced user had a password
    // set before enforcement was turned on; refuse the local session anyway.)
    match sso_enforced_for(&deps, &email, Some(user_id)).await {
        Ok(Some(org_slug)) => {
            return Redirect::to(&sso_start_path(&org_slug, next)).into_response()
        }
        Ok(None) => {}
        Err(err) => return internal(err),
    }
    // A correct password is a re-authentication: the session is sudo-capable.
    let lifetime = effective_session_lifetime(&deps).await;
    let cookie = match deps.db.create_session(user_id, lifetime, 1).await {
        Ok(secret) => set_cookie_header(&secret, lifetime),
        Err(err) => return internal(err),
    };
    let target = next.unwrap_or("/");
    ([(header::SET_COOKIE, cookie)], Redirect::to(target)).into_response()
}

/// Decode an `application/x-www-form-urlencoded` body into a field map.
fn parse_form(body: &str) -> std::collections::HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

// -- SSO enforcement helpers (DB-only, shared with the hub auth flow) --------

/// Resolve the org whose **verified** domain captures `email`, together with
/// whether that org has an OIDC IdP configured and enforces SSO.
///
/// Returns `(org_slug, enforce_sso)` when the email's domain is captured by an
/// org *and* that org has an IdP; `None` otherwise.
async fn sso_target(deps: &ConsoleDeps, email: &str) -> Option<(String, bool)> {
    let domain = email.rsplit_once('@').map(|(_, d)| d.to_lowercase())?;
    let org_id = deps.db.org_for_domain(&domain).await.ok().flatten()?;
    let config = deps.db.idp_config(org_id).await.ok().flatten()?;
    let org = deps.db.org_by_id(org_id).await.ok().flatten()?;
    Some((org.slug, config.enforce_sso))
}

/// Decide whether a user is **subject to SSO enforcement**, returning the org
/// slug to redirect them into when they are.
///
/// A user is captured by an org two ways — verified domain or membership — and
/// either binds them to the IdP. If any such org has `enforce_sso = true`, this
/// returns `Some(org_slug)`; otherwise `None`.
///
/// # Errors
///
/// Returns an error only on an unexpected database failure while listing the
/// user's memberships.
async fn sso_enforced_for(
    deps: &ConsoleDeps,
    email: &str,
    user_id: Option<i64>,
) -> anyhow::Result<Option<String>> {
    if let Some((org_slug, true)) = sso_target(deps, email).await {
        return Ok(Some(org_slug));
    }
    if let Some(user_id) = user_id {
        let principal = Principal::user(user_id);
        let mut seen_slugs = std::collections::HashSet::new();
        for (scope, _role) in deps
            .db
            .list_memberships_for(principal.kind.as_str(), principal.id)
            .await?
        {
            let Some(org_scope) = Scope::try_parse(&scope)
                .and_then(|scope| scope.as_str().split('/').next().map(str::to_string))
            else {
                continue;
            };
            if !seen_slugs.insert(org_scope.clone()) {
                continue;
            }
            let Some(org) = deps.db.org_by_stable_id(&org_scope).await? else {
                continue;
            };
            if let Some(config) = deps.db.idp_config(org.id).await? {
                if config.enforce_sso {
                    return Ok(Some(org.slug));
                }
            }
        }
    }
    Ok(None)
}

/// The OIDC start path that redirects a browser into an org's IdP login.
fn sso_start_path(org_slug: &str, next: Option<&str>) -> String {
    let mut path = format!("/auth/oidc/start?org={}", urlencode(org_slug));
    if let Some(next) = safe_return_path(next) {
        path.push_str("&next=");
        path.push_str(&urlencode(next));
    }
    path
}

/// Accept only an absolute path on this origin as a post-authentication target.
fn safe_return_path(next: Option<&str>) -> Option<&str> {
    next.map(str::trim).filter(|path| {
        path.starts_with('/')
            && !path.starts_with("//")
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
    })
}

// -- OIDC single sign-on ----------------------------------------------------
//
// The per-org OIDC authorization-code + PKCE flow (RFC-0004 Phase 5,
// console-dedup stage F). The flow logic itself lives in
// [`crate::auth::oidc`]; these handlers are its request edge. Its two network
// calls (the token exchange and the JWKS fetch) go through the
// [`HttpClient`](super::ports::HttpClient) port carried on [`ConsoleDeps`], so
// the handlers are wasm-clean and the native hub and the Worker mount them from
// this shared router.

/// `POST /auth/sso` body: the org to begin an SSO login against.
#[derive(serde::Deserialize)]
pub(crate) struct SsoForm {
    org: String,
    #[serde(default)]
    next: Option<String>,
}

/// `POST /auth/sso` — the no-JS "Sign in with SSO" button target.
///
/// Reached from the two-step login page when SSO is offered but not enforced;
/// it simply begins the OIDC flow for the named org, mirroring a `GET` of
/// `/auth/oidc/start?org=…`.
pub(crate) async fn login_sso(
    deps: ConsoleDeps,
    RequestStart(started): RequestStart,
    Form(form): Form<SsoForm>,
) -> Response {
    begin_oidc(
        &deps,
        &form.org,
        safe_return_path(form.next.as_deref()),
        started,
    )
    .await
}

/// `GET /auth/oidc/start?org=` query.
#[derive(serde::Deserialize)]
pub(crate) struct OidcStartQuery {
    org: String,
    #[serde(default)]
    next: Option<String>,
}

/// `GET /auth/oidc/start?org=<slug>` — redirect into the org's IdP.
///
/// Looks up the org and stages the authorization-code + PKCE flow, then
/// 302-redirects the browser to the IdP's authorization endpoint. An unknown
/// org or an org without an IdP renders a clean error page (no stack trace).
pub(crate) async fn oidc_start(
    deps: ConsoleDeps,
    RequestStart(started): RequestStart,
    Query(query): Query<OidcStartQuery>,
) -> Response {
    begin_oidc(&deps, &query.org, query.next.as_deref(), started).await
}

/// Shared "begin OIDC login" helper for the `GET` and `POST` entry points.
async fn begin_oidc(
    deps: &ConsoleDeps,
    org_slug: &str,
    next: Option<&str>,
    started: Instant,
) -> Response {
    let next = safe_return_path(next);
    let org = match deps.db.org_by_slug(org_slug).await {
        Ok(Some(org)) => org,
        Ok(None) => return sso_error("That organization does not exist.", started),
        Err(err) => return internal(err),
    };
    match crate::auth::oidc::begin_login(&deps.db, &deps.external_url, org.id, next).await {
        Ok(redirect) => Redirect::to(&redirect.url).into_response(),
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), org = %org_slug, "oidc begin failed");
            sso_error(
                "Single sign-on is not configured for that organization.",
                started,
            )
        }
    }
}

/// `GET /auth/oidc/callback?code=&state=` — complete the OIDC login.
///
/// Consumes the staged flow, exchanges the code, verifies the id_token, and on
/// success creates a sudo-capable session and redirects to the flow's
/// `redirect_after` (or `/`). Every failure renders a clean error page rather
/// than leaking internals.
pub(crate) async fn oidc_callback(
    deps: ConsoleDeps,
    RequestStart(started): RequestStart,
    Query(params): Query<crate::auth::oidc::CallbackParams>,
) -> Response {
    let login = match crate::auth::oidc::complete_login(
        &deps.db,
        deps.sealer.as_ref(),
        deps.http.as_ref(),
        &deps.external_url,
        &params,
    )
    .await
    {
        Ok(login) => login,
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "oidc callback failed");
            return sso_error("Sign-in could not be completed. Please try again.", started);
        }
    };
    // A fresh SSO sign-in is a re-authentication: the session is sudo-capable.
    let lifetime = effective_session_lifetime(&deps).await;
    let cookie = match deps.db.create_session(login.user_id, lifetime, 1).await {
        Ok(secret) => set_cookie_header(&secret, lifetime),
        Err(err) => return internal(err),
    };
    // Honor the staged redirect only for same-origin relative paths (a leading
    // single `/`), so a forged `next` can never bounce the browser off-site.
    let target = safe_return_path(login.redirect_after.as_deref()).unwrap_or("/");
    ([(header::SET_COOKIE, cookie)], Redirect::to(&target)).into_response()
}

/// Render a clean SSO error page (no stack traces).
fn sso_error(message: &str, started: Instant) -> Response {
    Html(console::login_page(Some(message), None, None, started)).into_response()
}

// -- query / form param shapes ----------------------------------------------

/// `?page=N` extractor for the paginated console lists (orgs, audit).
#[derive(serde::Deserialize, Default)]
pub(crate) struct PageQuery {
    page: Option<usize>,
}

impl PageQuery {
    /// The requested 1-based page, clamped to at least 1.
    fn page(&self) -> usize {
        self.page.unwrap_or(1).max(1)
    }
}

/// The two independent page parameters of the org dashboard.
#[derive(serde::Deserialize, Default)]
pub(crate) struct DashboardPages {
    registries_page: Option<usize>,
    members_page: Option<usize>,
}

impl DashboardPages {
    fn registries(&self) -> usize {
        self.registries_page.unwrap_or(1).max(1)
    }
    fn members(&self) -> usize {
        self.members_page.unwrap_or(1).max(1)
    }
}

/// A form carrying only the CSRF synchronizer token.
#[derive(serde::Deserialize)]
pub(crate) struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

// -- magic-link / logout ----------------------------------------------------

/// `GET /auth/magic?token=` query.
#[derive(serde::Deserialize)]
pub(crate) struct MagicQuery {
    token: String,
    #[serde(default)]
    next: Option<String>,
}

/// `GET /auth/magic?token=<secret>` — consume the link, sign the user in.
///
/// Finds or creates the user by the link's bound email, creates a sudo-capable
/// session, sets the `__Host-` cookie, and redirects to `/`. An unknown,
/// expired, or replayed link returns the login page with an error.
pub(crate) async fn magic_consume(
    deps: ConsoleDeps,
    RequestStart(started): RequestStart,
    Query(query): Query<MagicQuery>,
) -> Response {
    let email = match deps.db.consume_magic_link(&query.token).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            return Html(console::login_page(
                Some("That sign-in link is invalid or expired. Request a new one."),
                None,
                safe_return_path(query.next.as_deref()),
                started,
            ))
            .into_response()
        }
        Err(err) => return internal(err),
    };
    let user_id = match deps.db.find_or_create_user(&email).await {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    let lifetime = effective_session_lifetime(&deps).await;
    let cookie = match deps.db.create_session(user_id, lifetime, 1).await {
        Ok(secret) => set_cookie_header(&secret, lifetime),
        Err(err) => return internal(err),
    };
    let target = safe_return_path(query.next.as_deref()).unwrap_or("/");
    ([(header::SET_COOKIE, cookie)], Redirect::to(target)).into_response()
}

/// `GET /logout` — shows the non-mutating logout confirmation form.
pub(crate) async fn logout_form(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    Html(console::logout_page(
        &session.email,
        &session.csrf(),
        started,
    ))
    .into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct LogoutForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /logout` — revokes the caller's session after CSRF validation.
pub(crate) async fn logout(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    if let Err(error) = deps.db.revoke_session(&session.secret).await {
        return internal(error);
    }
    let cleared = format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, cleared)], Redirect::to("/login")).into_response()
}

// -- account ----------------------------------------------------------------

/// `GET /-/account` — the profile page (email, sessions, tokens, passkeys).
pub(crate) async fn account(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let tokens = match deps.db.list_tokens_for(session.principal()).await {
        Ok(tokens) => tokens,
        Err(err) => return internal(err),
    };
    let password_set = match deps.db.user_has_password(session.auth.user_id).await {
        Ok(set) => set,
        Err(err) => return internal(err),
    };
    Html(console::account_page(
        &session.email,
        &session.csrf(),
        &tokens,
        password_set,
        None,
        started,
    ))
    .into_response()
}

/// `POST /-/account/password` body: the CSRF token and the new password.
#[derive(serde::Deserialize)]
pub(crate) struct SetPasswordForm {
    #[serde(default)]
    csrf: String,
    password: String,
}

/// `POST /-/account/password` — set or change the logged-in user's password.
///
/// Session-authed, CSRF-protected, and **sudo-gated**. A member of an
/// SSO-enforced org is refused (a local password would bypass IdP
/// deprovisioning). On success it revokes every session, then mints a fresh
/// sudo session for this browser.
pub(crate) async fn account_set_password(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<SetPasswordForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    match sso_enforced_for(&deps, &session.email, Some(session.auth.user_id)).await {
        Ok(Some(_)) => {
            let tokens = deps
                .db
                .list_tokens_for(session.principal())
                .await
                .unwrap_or_default();
            let password_set = deps
                .db
                .user_has_password(session.auth.user_id)
                .await
                .unwrap_or(false);
            return (
                StatusCode::FORBIDDEN,
                Html(console::account_page(
                    &session.email,
                    &session.csrf(),
                    &tokens,
                    password_set,
                    Some(
                        "Your organization requires single sign-on; \
                         passwords cannot be set. Sign in through your identity provider.",
                    ),
                    started,
                )),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(err) => return internal(err),
    }
    if form.password.is_empty() || form.password.len() > 1024 {
        let tokens = deps
            .db
            .list_tokens_for(session.principal())
            .await
            .unwrap_or_default();
        let password_set = deps
            .db
            .user_has_password(session.auth.user_id)
            .await
            .unwrap_or(false);
        return Html(console::account_page(
            &session.email,
            &session.csrf(),
            &tokens,
            password_set,
            Some("Enter a password between 1 and 1024 characters."),
            started,
        ))
        .into_response();
    }
    let hash = match crate::auth::password::hash_password(&form.password) {
        Ok(hash) => hash,
        Err(err) => return internal(err),
    };
    if let Err(err) = deps.db.set_user_password(session.auth.user_id, &hash).await {
        return internal(err);
    }
    if let Err(err) = deps.db.revoke_all_user_sessions(session.auth.user_id).await {
        return internal(err);
    }
    let lifetime = effective_session_lifetime(&deps).await;
    let cookie = match deps
        .db
        .create_session(session.auth.user_id, lifetime, 1)
        .await
    {
        Ok(secret) => set_cookie_header(&secret, lifetime),
        Err(err) => return internal(err),
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to("/-/account")).into_response()
}

/// `POST /-/account/sessions/revoke-all` — sign out of every browser.
pub(crate) async fn account_revoke_all_sessions(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if let Err(err) = deps.db.revoke_all_user_sessions(session.auth.user_id).await {
        return internal(err);
    }
    let cleared = format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, cleared)], Redirect::to("/login")).into_response()
}

// -- passkeys / WebAuthn ----------------------------------------------------

/// `GET /-/account/passkeys` — list the user's passkeys and offer to add one.
pub(crate) async fn passkeys(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let creds = match deps.db.list_user_credentials(session.auth.user_id).await {
        Ok(c) => c,
        Err(err) => return internal(err),
    };
    let nonce = crate::auth::webauthn::new_challenge();
    let html = console::passkeys_page(&session.email, &session.csrf(), &creds, &nonce, started);
    passkey_html_response(html, &nonce)
}

/// A `POST /-/account/passkeys/remove` body: a CSRF token and the passkey id.
#[derive(serde::Deserialize)]
pub(crate) struct PasskeyRemoveForm {
    #[serde(default)]
    csrf: String,
    id: i64,
}

/// `POST /-/account/passkeys/remove` — delete one of the signed-in user's
/// passkeys, then return to the passkeys page.
///
/// Scoped to the session user, so a request can only remove the caller's own
/// credential. Removing a passkey never locks the account out — email
/// magic-link sign-in remains available.
pub(crate) async fn passkeys_remove(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<PasskeyRemoveForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    match deps
        .db
        .delete_webauthn_credential(session.auth.user_id, form.id)
        .await
    {
        Ok(_) => Redirect::to("/-/account/passkeys").into_response(),
        Err(err) => internal(err),
    }
}

/// Build an `Html` response carrying the per-request passkey CSP.
fn passkey_html_response(html: String, nonce: &str) -> Response {
    let csp = format!("default-src 'self'; script-src 'self' 'nonce-{nonce}'");
    ([(header::CONTENT_SECURITY_POLICY, csp)], Html(html)).into_response()
}

/// A passkey registration `begin` body: a CSRF token.
#[derive(serde::Deserialize)]
pub(crate) struct PasskeyBeginForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /-/account/passkeys/begin` — stage a registration challenge (JSON).
pub(crate) async fn passkeys_begin(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<PasskeyBeginForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let rp = match crate::auth::webauthn::relying_party(&deps.external_url) {
        Ok(rp) => rp,
        Err(err) => return internal(err),
    };
    let rp_name = match console::brand() {
        "" => "Registry Hub",
        brand => brand,
    };
    match crate::auth::webauthn::begin_registration(
        &deps.db,
        session.auth.user_id,
        &session.email,
        &rp.id,
        rp_name,
    )
    .await
    {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => internal(err),
    }
}

/// A passkey registration `finish` body, with base64url binary fields.
#[derive(serde::Deserialize)]
pub(crate) struct PasskeyFinishBody {
    csrf: String,
    #[serde(default)]
    label: Option<String>,
    client_data_json: String,
    attestation_object: String,
}

/// `POST /-/account/passkeys/finish` — verify + persist the new credential.
pub(crate) async fn passkeys_finish(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Json(body): Json<PasskeyFinishBody>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &body.csrf) {
        return *resp;
    }
    match sso_enforced_for(&deps, &session.email, Some(session.auth.user_id)).await {
        Ok(Some(_)) => {
            return (
                StatusCode::FORBIDDEN,
                "Your organization requires single sign-on; passkeys cannot be enrolled.",
            )
                .into_response();
        }
        Ok(None) => {}
        Err(err) => return internal(err),
    }
    let rp = match crate::auth::webauthn::relying_party(&deps.external_url) {
        Ok(rp) => rp,
        Err(err) => return internal(err),
    };
    let (client_data_json, attestation_object) = match (
        B64URL.decode(&body.client_data_json),
        B64URL.decode(&body.attestation_object),
    ) {
        (Ok(c), Ok(a)) => (c, a),
        _ => return (StatusCode::BAD_REQUEST, "malformed base64url fields").into_response(),
    };
    let response = crate::auth::webauthn::RegistrationResponse {
        client_data_json,
        attestation_object,
    };
    let label = body.label.as_deref().filter(|s| !s.is_empty());
    match crate::auth::webauthn::finish_registration(
        &deps.db,
        session.auth.user_id,
        &rp.id,
        &rp.origin,
        &response,
        label,
    )
    .await
    {
        Ok(credential_id) => {
            Json(serde_json::json!({ "credential_id": credential_id })).into_response()
        }
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "passkey registration rejected");
            (StatusCode::BAD_REQUEST, "passkey registration failed").into_response()
        }
    }
}

/// A passkey login `finish` body, with base64url binary fields.
#[derive(serde::Deserialize)]
pub(crate) struct PasskeyLoginBody {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

/// `POST /auth/passkey/finish` — verify the assertion, sign the user in.
///
/// Pre-auth. On success creates a sudo-capable session and returns `200`; a
/// member of an SSO-enforced org is steered to the IdP with a `403` instead.
pub(crate) async fn passkey_login_finish(
    deps: ConsoleDeps,
    Json(body): Json<PasskeyLoginBody>,
) -> Response {
    let rp = match crate::auth::webauthn::relying_party(&deps.external_url) {
        Ok(rp) => rp,
        Err(err) => return internal(err),
    };
    let (client_data_json, authenticator_data, signature) = match (
        B64URL.decode(&body.client_data_json),
        B64URL.decode(&body.authenticator_data),
        B64URL.decode(&body.signature),
    ) {
        (Ok(c), Ok(a), Ok(s)) => (c, a, s),
        _ => return (StatusCode::BAD_REQUEST, "malformed base64url fields").into_response(),
    };
    let response = crate::auth::webauthn::AssertionResponse {
        credential_id: body.credential_id,
        client_data_json,
        authenticator_data,
        signature,
    };
    let user_id = match crate::auth::webauthn::finish_assertion(
        &deps.db, &rp.id, &rp.origin, &response,
    )
    .await
    {
        Ok(id) => id,
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "passkey assertion rejected");
            return (StatusCode::UNAUTHORIZED, "passkey sign-in failed").into_response();
        }
    };
    match deps.db.user_email(user_id).await {
        Ok(Some(email)) => match sso_enforced_for(&deps, &email, Some(user_id)).await {
            Ok(Some(org_slug)) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "redirect": sso_start_path(&org_slug, None) })),
                )
                    .into_response();
            }
            Ok(None) => {}
            Err(err) => return internal(err),
        },
        Ok(None) => return (StatusCode::UNAUTHORIZED, "passkey sign-in failed").into_response(),
        Err(err) => return internal(err),
    }
    let lifetime = effective_session_lifetime(&deps).await;
    let cookie = match deps.db.create_session(user_id, lifetime, 1).await {
        Ok(secret) => set_cookie_header(&secret, lifetime),
        Err(err) => return internal(err),
    };
    (
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "ok": true })),
    )
        .into_response()
}

/// `POST /auth/passkey/begin` — stage a usernameless assertion challenge (JSON).
///
/// Pre-auth (the login path). Returns the
/// [`AssertionChallenge`](crate::auth::webauthn::AssertionChallenge) the inline
/// login script feeds to `navigator.credentials.get`.
///
/// Rate-limited per source IP — the [`resolved_client_ip`] the ingress layer
/// stamped (see [`CLIENT_IP_HEADER`]) — under the same
/// [`RateClass::MagicLinkIp`](crate::ratelimit::RateClass::MagicLinkIp) spray
/// bound as magic-link issuance.
pub(crate) async fn passkey_login_begin(deps: ConsoleDeps, headers: HeaderMap) -> Response {
    // Rate-limit assertion-challenge issuance per source IP, the same pre-auth
    // spray bound as magic-link issuance.
    let now = crate::clock::now_unix_secs();
    let ip = resolved_client_ip(&headers);
    if let crate::ratelimit::RateDecision::Limited { retry_after } = deps
        .ratelimit
        .check(crate::ratelimit::RateClass::MagicLinkIp, &ip, now)
        .await
    {
        return too_many_requests(retry_after);
    }
    let rp = match crate::auth::webauthn::relying_party(&deps.external_url) {
        Ok(rp) => rp,
        Err(err) => return internal(err),
    };
    match crate::auth::webauthn::begin_assertion(&deps.db, &rp.id).await {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => internal(err),
    }
}

// -- device approval (RFC 8628) ---------------------------------------------

/// `GET /activate?user_code=` query.
#[derive(Default, serde::Deserialize)]
pub(crate) struct ActivateQuery {
    user_code: Option<String>,
    message: Option<String>,
}

/// Rate-limit a device-activation request for the signed-in `session`.
///
/// The `/activate` approve surface keys a pending device grant solely on its
/// `user_code` with no ownership predicate, so without a throttle a signed-in
/// user could enumerate the code space at full speed to discover and inspect
/// (or hijack) other users' in-flight grants (sec L-4). This meters under
/// [`RateClass::DeviceActivate`](crate::ratelimit::RateClass::DeviceActivate)
/// keyed on the **session user combined with the client IP** (the
/// [`resolved_client_ip`] the ingress layer stamped — see [`CLIENT_IP_HEADER`]),
/// so neither a single account nor a single source can spin the wheel quickly,
/// and returns `Some(429)` (with `Retry-After`) when the budget is exhausted.
/// Both the GET form and the POST submit call it. (The future polling endpoint,
/// when wired, should meter the same class on the requesting CLI principal.)
async fn activate_rate_limited(
    deps: &ConsoleDeps,
    session: &Session,
    headers: &HeaderMap,
) -> Option<Response> {
    let ip = resolved_client_ip(headers);
    let key = format!("{}|{ip}", session.auth.user_id);
    match deps
        .ratelimit
        .check(
            crate::ratelimit::RateClass::DeviceActivate,
            &key,
            crate::clock::now_unix_secs(),
        )
        .await
    {
        crate::ratelimit::RateDecision::Limited { retry_after } => {
            Some(too_many_requests(retry_after))
        }
        crate::ratelimit::RateDecision::Allowed => None,
    }
}

/// `GET /activate` — the device-approval page.
///
/// Prefills the user code from `?user_code=` and, when it resolves to a live
/// pending grant, shows the requested scope/permissions and the approve form.
pub(crate) async fn activate_form(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Query(query): Query<ActivateQuery>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Some(resp) = activate_rate_limited(&deps, &session, &headers).await {
        return resp;
    }
    let user_code = query.user_code.unwrap_or_default();
    let request = if user_code.is_empty() {
        None
    } else {
        match deps.db.pending_device_request(&user_code).await {
            Ok(Some((scope, permissions))) => {
                let display = match deps.db.authorization_scope_display_path(&scope).await {
                    Ok(Some(display)) => display,
                    Ok(None) => scope,
                    Err(error) => return internal(error),
                };
                Some((display, permissions))
            }
            Ok(None) => None,
            Err(err) => return internal(err),
        }
    };
    let request_ref = request.as_ref().map(|(s, p)| (s.as_str(), p.as_slice()));
    Html(console::activate_page(
        &session.email,
        &session.csrf(),
        &user_code,
        request_ref,
        query.message.as_deref(),
        started,
    ))
    .into_response()
}

/// `POST /activate` form: the user code and the approve/deny decision.
#[derive(serde::Deserialize)]
pub(crate) struct ActivateForm {
    #[serde(default)]
    csrf: String,
    user_code: String,
    decision: String,
}

/// `POST /activate` — approve or deny a device grant.
///
/// Approval clamps the minted token to the approver's current grants (the
/// clamp lives in [`Database::approve_device`](crate::db::Database::approve_device));
/// denial marks the grant denied. Redirects back to `/activate` with a result
/// message.
pub(crate) async fn activate_submit(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<ActivateForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Some(resp) = activate_rate_limited(&deps, &session, &headers).await {
        return resp;
    }
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let message = if form.decision == "approve" {
        let grants = match session.grants(&deps.db).await {
            Ok(grants) => grants,
            Err(err) => return internal(err),
        };
        match deps
            .db
            .approve_device(&form.user_code, session.principal(), &grants)
            .await
        {
            Ok(true) => "Approved. Return to your terminal — the CLI will continue.",
            Ok(false) => "That code is unknown, already resolved, or expired.",
            Err(err) => return internal(err),
        }
    } else {
        match deps.db.deny_device(&form.user_code).await {
            Ok(_) => "Denied.",
            Err(err) => return internal(err),
        }
    };
    Redirect::to(&format!("/activate?message={}", urlencode(message))).into_response()
}

// -- orgs -------------------------------------------------------------------

/// `GET /-/orgs` — the user's org list.
pub(crate) async fn orgs(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Query(params): Query<PageQuery>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let result = async {
        let grants = session.grants(&deps.db).await?;
        let mut orgs = Vec::new();
        for org in deps.db.list_orgs().await? {
            if grants_allow(
                &deps.db,
                &grants,
                Permission::Read,
                &Scope::parse(&org.stable_id),
            )
            .await
            {
                orgs.push(org);
            }
        }
        let can_create = may_create_org(&deps.db, &session).await?;
        let is_instance_admin = iam::allow(
            &grants,
            Permission::IamAdmin,
            &iam::AuthorizationContext::instance(),
        );
        Ok::<_, anyhow::Error>((orgs, can_create, is_instance_admin))
    }
    .await;
    match result {
        Ok((orgs, can_create, is_instance_admin)) => Html(console::orgs_page(
            &session.email,
            &orgs,
            can_create,
            is_instance_admin,
            params.page(),
            started,
        ))
        .into_response(),
        Err(err) => internal(err),
    }
}

/// `GET /-/caches` — the global binary-caches list (the masthead **caches** tab).
///
/// Caches are a signed-in surface: an anonymous visitor is redirected to log in
/// unless the instance has opted caches into public visibility (`caches_public`),
/// in which case only public caches are listed. A signed-in viewer sees public
/// caches plus any cache readable on an org they belong to.
pub(crate) async fn caches(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match resolve_session_from_headers(&deps.db, &headers).await {
        Ok(Some(r)) => Some(Session {
            secret: r.secret,
            auth: r.auth,
            email: r.email,
        }),
        Ok(None) => None,
        Err(err) => return internal(err),
    };
    // Logged-out visitors only reach this surface when the instance opts in.
    if session.is_none() && !console::caches_public() {
        return Redirect::to("/login").into_response();
    }
    let result = async {
        let grants = match &session {
            Some(s) => s.grants(&deps.db).await?,
            None => Vec::new(),
        };
        let organizations: std::collections::HashMap<i64, (String, String)> = deps
            .db
            .list_orgs()
            .await?
            .into_iter()
            .map(|o| (o.id, (o.slug, o.stable_id)))
            .collect();
        let mut rows = Vec::new();
        for c in deps.db.list_binary_caches().await? {
            let (org_slug, _) = c
                .org_id
                .and_then(|id| organizations.get(&id).cloned())
                .unwrap_or_default();
            let management_access = grants_allow(
                &deps.db,
                &grants,
                Permission::Read,
                &Scope::parse(&c.scope_key),
            )
            .await;
            let readable = c.visibility == "public" || management_access;
            if readable {
                rows.push(console::CacheListRow {
                    org_slug,
                    slug: c.slug,
                    name: c.name,
                    visibility: c.visibility,
                    management_access,
                });
            }
        }
        Ok::<_, anyhow::Error>(rows)
    }
    .await;
    match result {
        Ok(rows) => Html(console::caches_page(
            session.as_ref().map(|s| s.email.as_str()),
            &rows,
            started,
        ))
        .into_response(),
        Err(err) => internal(err),
    }
}

/// Whether the instance signup policy permits `session`'s user to create an org.
///
/// # Errors
///
/// Returns an error on database failure.
async fn may_create_org(db: &Database, session: &Session) -> anyhow::Result<bool> {
    if db.signup_policy().await? == crate::db::SignupPolicy::Open {
        return Ok(true);
    }
    let user_id = session.auth.user_id;
    if db.user_has_any_membership(user_id).await? {
        return Ok(true);
    }
    let grants = session.grants(db).await?;
    if iam::allow(
        &grants,
        Permission::IamAdmin,
        &iam::AuthorizationContext::instance(),
    ) {
        return Ok(true);
    }
    if db.has_pending_invitation(&session.email).await? {
        return Ok(true);
    }
    Ok(false)
}

/// `GET /-/org/{org}` — the org dashboard.
pub(crate) async fn org_dashboard(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
) -> Response {
    org_view(deps, headers, started, path, pages, "overview").await
}

/// `GET /-/org/{org}/registries` — the organization's registry inventory.
pub(crate) async fn org_registries(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
) -> Response {
    org_view(deps, headers, started, path, pages, "registries").await
}

/// `GET /-/org/{org}/caches` — the org's binary-caches tab.
pub(crate) async fn org_caches(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
) -> Response {
    org_view(deps, headers, started, path, pages, "caches").await
}

/// `GET /-/org/{org}/projects` — the org's projects tab.
pub(crate) async fn org_projects(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
) -> Response {
    org_view(deps, headers, started, path, pages, "projects").await
}

/// `GET /-/org/{org}/members` — the org's members tab.
pub(crate) async fn org_members(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
) -> Response {
    org_view(deps, headers, started, path, pages, "members").await
}

/// `GET /-/org/{org}/storage-bindings` — the organization's bindings inventory.
pub(crate) async fn org_storage_bindings(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
) -> Response {
    org_view(deps, headers, started, path, pages, "storage-bindings").await
}

/// Renders an organization infrastructure or policy collection in the shared shell.
pub(crate) async fn org_settings_collection(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
    section: &'static str,
) -> Response {
    org_view(deps, headers, started, path, pages, section).await
}

/// Renders a dedicated organization resource-creation page.
pub(crate) async fn org_new_resource(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    resource: &'static str,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let scope = organization_scope(&deps.db, &org_slug).await;
    let permission = match resource {
        "storage-binding" => Permission::StorageBindingManage,
        "member-invitation" => Permission::MembersManage,
        "signing-key" => Permission::KeysManage,
        _ => Permission::RegistryConfigure,
    };
    if let Some(deny) = require_org_perm(&deps, &session, &scope, permission).await {
        return *deny;
    }
    let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let html = match resource {
            "storage-binding" => console::org_new_storage_binding_page(
                &session.email,
                &org,
                &session.csrf(),
                &navigation,
                started,
            ),
            "member-invitation" => console::org_new_member_invitation_page(
                &session.email,
                &org,
                &session.csrf(),
                &navigation,
                started,
            ),
            "signing-key" => console::org_new_signing_key_page(
                &session.email,
                &org,
                &session.csrf(),
                &navigation,
                started,
            ),
            "webhook" => console::org_new_webhook_page(
                &session.email,
                &org,
                &session.csrf(),
                &navigation,
                started,
            ),
            _ => anyhow::bail!("unknown organization resource workflow"),
        };
        Ok::<_, anyhow::Error>(Some(html))
    }
    .await;
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => internal(error),
    }
}

/// `GET /-/org/{org}/danger` — the org's danger-zone tab (delete org).
pub(crate) async fn org_danger(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
) -> Response {
    org_view(deps, headers, started, path, pages, "danger").await
}

/// Loads every stable network boundary in one owner scope.
async fn all_network_boundaries(
    db: &Database,
    owner_scope_key: &str,
) -> anyhow::Result<Vec<crate::db::NetworkBoundaryRecord>> {
    let mut records = Vec::new();
    let mut cursor = None;
    loop {
        let page = db
            .list_network_boundaries_page(owner_scope_key, 100, cursor.as_deref())
            .await?;
        records.extend(page.records);
        let Some(next_cursor) = page.next_cursor else {
            return Ok(records);
        };
        cursor = Some(next_cursor);
    }
}

/// Loads every stable delivery endpoint in one owner scope.
async fn all_delivery_endpoints(
    db: &Database,
    owner_scope_key: &str,
) -> anyhow::Result<Vec<crate::db::DeliveryEndpointRecord>> {
    let mut records = Vec::new();
    let mut cursor = None;
    loop {
        let page = db
            .list_delivery_endpoints_page(owner_scope_key, 100, cursor.as_deref())
            .await?;
        records.extend(page.records);
        let Some(next_cursor) = page.next_cursor else {
            return Ok(records);
        };
        cursor = Some(next_cursor);
    }
}

/// Renders one organization settings section from the shared data model.
async fn org_view(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    Query(pages): Query<DashboardPages>,
    active: &str,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = organization_scope(&deps.db, &org_slug).await;
    let Some(page) = OrgPage::parse(active) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let required = ORG_PAGES
        .iter()
        .find(|spec| spec.key == page)
        .map_or(Permission::Read, |spec| spec.permission);
    if !session.allows(&deps.db, required, &scope).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let can_manage_storage = session
            .allows(&deps.db, Permission::StorageBindingManage, &scope)
            .await;
        let projects = deps.db.list_projects(org.id).await?;
        let (bindings, managed_bindings) = if can_manage_storage {
            let managed = deps.db.list_storage_bindings(org.id).await?;
            let summaries = managed
                .iter()
                .map(crate::db::StorageBindingReadSummary::from)
                .collect();
            (summaries, Some(managed))
        } else {
            (
                deps.db.list_storage_binding_read_summaries(org.id).await?,
                None,
            )
        };
        let mut caches = Vec::new();
        for c in deps.db.list_binary_caches_for_org(org.id).await? {
            if c.deleted_at.is_some() {
                continue;
            }
            let usage = deps.db.cache_usage(c.id).await?;
            let signed = deps
                .db
                .signing_key_usage(&c.stable_id, "narinfo")
                .await?
                .is_some_and(|usage| usage.state == "active");
            caches.push(console::CacheSummary {
                slug: c.slug,
                name: c.name,
                visibility: c.visibility,
                signed,
                priority: c.priority,
                used_bytes: usage.used_bytes,
                object_count: usage.object_count,
            });
        }
        let registries: Vec<RegistryRecord> = deps
            .db
            .list_registries()
            .await?
            .into_iter()
            .filter(|r| r.org_id == Some(org.id))
            .collect();
        let domains = if matches!(active, "domains" | "delivery-endpoints") {
            deps.db.list_delivery_domains(&org.stable_id).await?
        } else {
            Vec::new()
        };
        let boundaries = if active == "network-boundaries" {
            all_network_boundaries(&deps.db, &org.stable_id).await?
        } else {
            Vec::new()
        };
        let endpoints = if active == "delivery-endpoints" {
            all_delivery_endpoints(&deps.db, &org.stable_id).await?
        } else {
            Vec::new()
        };
        let gateways = if active == "storage-gateways" {
            deps.db
                .list_storage_gateways(None)
                .await?
                .into_iter()
                .filter(|gateway| gateway.owner_scope_key == org.stable_id)
                .collect()
        } else {
            Vec::new()
        };
        let topology_defaults = if active == "topology-defaults" && can_manage_storage {
            let bearer = session.topology_bearer(&deps, Scope::parse(&org.stable_id))?;
            Some(
                deps.topology
                    .organization_topology_defaults(&bearer, org.slug.clone())
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            )
        } else {
            None
        };
        let can_manage = session
            .allows(&deps.db, Permission::MembersManage, &scope)
            .await;
        let members = load_members(&deps.db, &org.stable_id).await?;
        let invitations = if can_manage && active == "members" {
            let bearer = session.topology_bearer(&deps, Scope::parse(&org.stable_id))?;
            deps.topology
                .invitations(&bearer, org.slug.clone())
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
        } else {
            Vec::new()
        };
        let owner_count = members.iter().filter(|m| m.role == "owner").count();
        let can_configure = session
            .allows(&deps.db, Permission::RegistryConfigure, &scope)
            .await;
        let can_delete = session.allows(&deps.db, Permission::IamAdmin, &scope).await;
        Ok::<_, anyhow::Error>(Some(console::org_dashboard(
            &session.email,
            &org,
            &session.csrf(),
            &projects,
            &registries,
            &members,
            &invitations,
            &bindings,
            managed_bindings.as_deref(),
            &caches,
            &domains,
            &boundaries,
            &endpoints,
            &gateways,
            topology_defaults.as_ref(),
            can_manage,
            can_configure,
            can_manage_storage,
            can_delete,
            owner_count,
            pages.registries(),
            pages.members(),
            active,
            &navigation,
            started,
        )))
    }
    .await;
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Load an org's direct members as console rows (resolving user emails).
async fn load_members(
    db: &Database,
    org_scope_key: &str,
) -> anyhow::Result<Vec<console::MemberRow>> {
    let mut rows = Vec::new();
    for (kind, id, role) in db.list_members_of_scope(org_scope_key).await? {
        let label = if kind == "user" {
            db.user_email(id)
                .await?
                .unwrap_or_else(|| format!("user:{id}"))
        } else {
            format!("{kind}:{id}")
        };
        rows.push(console::MemberRow {
            label,
            kind,
            id,
            role,
        });
    }
    Ok(rows)
}

/// `GET /-/org/{org}/audit-log` — the organization audit feed.
pub(crate) async fn org_audit_log(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    Query(params): Query<PageQuery>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = organization_scope(&deps.db, &org_slug).await;
    if !session
        .allows(&deps.db, Permission::AuditRead, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "audit read requires admin").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let rows = deps.db.list_audit(&org.stable_id).await?;
        Ok::<_, anyhow::Error>(Some(console::audit_page(
            &session.email,
            &org,
            &rows,
            params.page(),
            &navigation,
            started,
        )))
    }
    .await;
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

// -- binary caches ----------------------------------------------------------

/// `POST /-/org/{org}/caches/{slug}` form: mutable cache settings.
#[derive(serde::Deserialize)]
pub(crate) struct CacheUpdateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    visibility: String,
    #[serde(default)]
    nix_priority: String,
    #[serde(default)]
    compression: String,
    #[serde(default)]
    want_mass_query: Option<String>,
    #[serde(default)]
    expected_resource_version: String,
}

/// Normalize a visibility form value, defaulting to `private`.
fn cache_visibility(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        "" | "private" => Some("private"),
        "internal" => Some("internal"),
        "public" => Some("public"),
        _ => None,
    }
}

/// Renders a cache detail page from normalized topology inventories.
///
/// `notice` surfaces the last action's outcome.
///
/// Returns `404` when the cache is missing or not owned by `org`.
async fn render_cache_detail(
    deps: &ConsoleDeps,
    session: &Session,
    org: &OrgRecord,
    cache: &crate::db::BinaryCache,
    can_admin: bool,
    active: &str,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    let scope = Scope::parse(&cache.scope_key);
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let result = async {
        let usage = deps.db.cache_usage(cache.id).await?;
        let placements =
            placement_overview_rows(deps, crate::db::SurfaceTarget::BinaryCache(cache.id)).await?;
        let (policies, equivalences) =
            placement_policy_overview_rows(deps, crate::db::SurfaceTarget::BinaryCache(cache.id))
                .await?;
        let routes =
            delivery_route_overview_rows(deps, crate::db::SurfaceTarget::BinaryCache(cache.id))
                .await?;
        let mut retention = Vec::new();
        for subscription in deps
            .db
            .list_cache_retention_subscriptions_topology(cache.id)
            .await?
        {
            let registry = deps.db.registry_by_id(subscription.registry_id).await?;
            retention.push(console::RetentionSubscriptionOverviewRow {
                id: subscription.id,
                registry: registry
                    .map(|record| record.slug)
                    .unwrap_or_else(|| format!("registry:{}", subscription.registry_id)),
                state: subscription.refresh_state,
                selector: subscription.selector_json,
                revision: subscription.last_successful_revision,
            });
        }
        let mut manual_roots = Vec::new();
        for root in deps
            .db
            .list_manual_retention_roots_topology(cache.id)
            .await?
        {
            let lease = match root.current_lease_id.as_deref() {
                Some(lease_id) => deps.db.retention_lease(lease_id).await?,
                None => None,
            };
            manual_roots.push(console::ManualRetentionRootOverviewRow {
                id: root.id,
                store_hash: root.store_hash,
                protection_kind: root.protection_kind,
                reason: root.reason,
                lease_id: lease.as_ref().map(|lease| lease.id.clone()),
                lease_state: lease.as_ref().map(|lease| lease.state.clone()),
                lease_expires_at: lease.as_ref().map(|lease| lease.expires_at),
                deleted_at: root.deleted_at,
                resource_version: root.resource_version,
            });
        }
        let mut population = Vec::new();
        for target in deps.db.list_cache_population_targets(cache.id).await? {
            let registry = deps.db.registry_by_id(target.registry_id).await?;
            population.push(console::PopulationTargetOverviewRow {
                id: target.id,
                registry: registry
                    .map(|record| record.slug)
                    .unwrap_or_else(|| format!("registry:{}", target.registry_id)),
                trigger: target.trigger_kind,
                required: target.required,
                enabled: target.enabled,
            });
        }
        let signing_usage = deps
            .db
            .signing_key_usage(&cache.stable_id, "narinfo")
            .await?;
        let signing_keys = if active == "signing-key" && can_admin {
            let bearer = session.topology_bearer(deps, Scope::parse(&org.stable_id))?;
            deps.topology
                .signing_keys(&bearer, org.stable_id.clone())
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
        } else {
            Vec::new()
        };
        Ok::<_, anyhow::Error>(console::cache_page(
            &session.email,
            &org.slug,
            &session.csrf(),
            cache,
            &placements,
            &policies,
            &equivalences,
            &routes,
            &retention,
            &manual_roots,
            &population,
            &usage,
            signing_usage
                .as_ref()
                .is_some_and(|usage| usage.state == "active"),
            signing_usage.as_ref(),
            &signing_keys,
            can_admin,
            active,
            notice,
            &navigation,
            started,
        ))
    }
    .await;
    match result {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

/// Resolves placement records to the id-free rows shown on surface overviews.
async fn placement_overview_rows(
    deps: &ConsoleDeps,
    surface: crate::db::SurfaceTarget,
) -> anyhow::Result<Vec<console::PlacementOverviewRow>> {
    let mut rows = Vec::new();
    for placement in deps.db.list_surface_placements(surface).await? {
        let binding_name = deps
            .db
            .storage_binding(placement.storage_binding_id)
            .await?
            .map(|binding| binding.name)
            .unwrap_or_else(|| "unavailable".to_string());
        rows.push(console::PlacementOverviewRow {
            name: placement.name,
            binding_name,
            prefix: placement.prefix,
            role: placement.derived_role,
            state: placement.state,
            desired_state: placement.desired_state,
            completeness: placement.completeness,
            read_enabled: placement.effective_read_enabled,
            desired_read_enabled: placement.desired_read_enabled,
            read_order: placement.read_order,
            write_enabled: placement.effective_write_enabled,
            desired_authority: placement.authority_desired_placement_id == Some(placement.id),
            observed_authority: placement.authority_observed_placement_id == Some(placement.id),
            desired_generation: placement.authority_desired_generation,
            observed_generation: placement.authority_observed_generation,
            authority_state: placement.authority_reconciliation_state,
            resource_version: placement.resource_version,
        });
    }
    Ok(rows)
}

/// Resolves immutable policy revisions and confirmed equivalences for one surface.
async fn placement_policy_overview_rows(
    deps: &ConsoleDeps,
    surface: crate::db::SurfaceTarget,
) -> anyhow::Result<(
    Vec<console::PlacementPolicyOverviewRow>,
    Vec<console::PlacementEquivalenceOverviewRow>,
)> {
    let mut policies = Vec::new();
    for policy in deps.db.list_placement_policy_identities(surface).await? {
        let revisions = deps.db.list_placement_policy_revisions(&policy.id).await?;
        let current = policy
            .current_revision_id
            .as_deref()
            .and_then(|current_id| revisions.iter().find(|revision| revision.id == current_id));
        let newest = revisions.last();
        policies.push(console::PlacementPolicyOverviewRow {
            id: policy.id,
            name: policy.name,
            kind: newest
                .map(|revision| revision.spec.kind.clone())
                .unwrap_or_else(|| "unconfigured".to_string()),
            current_revision: current.map(|revision| revision.revision),
            revision_count: revisions.len(),
            latest_state: newest.map(|revision| revision.state.clone()),
            current_digest: current.and_then(|revision| revision.content_digest.clone()),
            resource_version: policy.resource_version,
        });
    }
    let equivalences = deps
        .db
        .list_placement_equivalences(surface)
        .await?
        .into_iter()
        .map(|equivalence| console::PlacementEquivalenceOverviewRow {
            id: equivalence.id,
            placement_a: equivalence.placement_a,
            placement_b: equivalence.placement_b,
            evidence_digest: equivalence.evidence_digest,
            state: equivalence.state,
            resource_version: equivalence.resource_version,
        })
        .collect();
    Ok((policies, equivalences))
}

/// Resolves normalized delivery routes into the shared registry/cache read model.
async fn delivery_route_overview_rows(
    deps: &ConsoleDeps,
    surface: crate::db::SurfaceTarget,
) -> anyhow::Result<Vec<console::DeliveryRouteOverviewRow>> {
    let mut rows = Vec::new();
    for route in deps.db.list_delivery_routes(surface).await? {
        let mut canonical_audiences = Vec::new();
        for audience in ["git", "nix_cache", "web"] {
            if deps
                .db
                .canonical_route(surface, audience)
                .await?
                .is_some_and(|canonical| canonical.delivery_route_id.as_str() == route.id.as_str())
            {
                canonical_audiences.push(audience.to_string());
            }
        }
        let endpoint = deps
            .db
            .delivery_endpoint(&route.endpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("delivery route references a missing endpoint"))?;
        let hostname = if let Some(domain_id) = endpoint.domain_id {
            deps.db
                .domain(domain_id)
                .await?
                .map(|domain| domain.hostname)
                .ok_or_else(|| anyhow::anyhow!("delivery endpoint references a missing domain"))?
        } else if let Some(bytes) = endpoint.ipv4_bytes.as_deref() {
            let octets = <[u8; 4]>::try_from(bytes)
                .map_err(|_| anyhow::anyhow!("delivery endpoint has malformed IPv4 bytes"))?;
            std::net::Ipv4Addr::from(octets).to_string()
        } else if let Some(bytes) = endpoint.ipv6_bytes.as_deref() {
            let octets = <[u8; 16]>::try_from(bytes)
                .map_err(|_| anyhow::anyhow!("delivery endpoint has malformed IPv6 bytes"))?;
            format!("[{}]", std::net::Ipv6Addr::from(octets))
        } else {
            return Err(anyhow::anyhow!("delivery endpoint has no host identity"));
        };
        let path = if route.base_path.is_empty() {
            "/".to_string()
        } else if route.base_path.starts_with('/') {
            route.base_path.clone()
        } else {
            format!("/{}", route.base_path)
        };
        let snapshot = deps
            .db
            .delivery_route_snapshot(&route.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("delivery route has no current snapshot"))?;
        let mut capabilities = Vec::new();
        if snapshot.spec.serves_git {
            capabilities.push("git");
        }
        if snapshot.spec.serves_cache {
            capabilities.push("cache");
        }
        if snapshot.spec.serves_web {
            capabilities.push("web");
        }
        rows.push(console::DeliveryRouteOverviewRow {
            id: route.id,
            url: delivery_route_url(&endpoint.scheme, &hostname, endpoint.effective_port, &path),
            mode: route.mode,
            capabilities,
            readiness: snapshot.observation_state,
            enabled: route.enabled,
            canonical_audiences,
        });
    }
    rows.sort_by(|left, right| {
        left.canonical_audiences
            .is_empty()
            .cmp(&right.canonical_audiences.is_empty())
            .then_with(|| right.enabled.cmp(&left.enabled))
            .then_with(|| left.url.cmp(&right.url))
    });
    Ok(rows)
}

/// Renders the client-visible URL from the endpoint's immutable identity.
fn delivery_route_url(scheme: &str, hostname: &str, effective_port: i64, path: &str) -> String {
    let default_port = matches!((scheme, effective_port), ("http", 80) | ("https", 443));
    if default_port {
        format!("{scheme}://{hostname}{path}")
    } else {
        format!("{scheme}://{hostname}:{effective_port}{path}")
    }
}

/// Resolve `(org, cache)` for a cache console route, enforcing that the cache
/// belongs to the org. Returns the deny/redirect response on any failure.
async fn cache_in_org(
    deps: &ConsoleDeps,
    org_slug: &str,
    cache_slug: &str,
) -> Result<(OrgRecord, crate::db::BinaryCache), Response> {
    let Some(org) = deps.db.org_by_slug(org_slug).await.map_err(internal)? else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    let Some(cache) = deps
        .db
        .binary_cache_by_slug(cache_slug)
        .await
        .map_err(internal)?
    else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    if cache.org_id != Some(org.id) || cache.deleted_at.is_some() {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    Ok((org, cache))
}

/// Resolves an org-owned cache before authorizing against its exact scope.
async fn cache_in_org_with_permission(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    cache_slug: &str,
    permission: Permission,
) -> Result<(OrgRecord, crate::db::BinaryCache, Scope), Response> {
    let (org, cache) = cache_in_org(deps, org_slug, cache_slug).await?;
    let scope = Scope::parse(&cache.scope_key);
    if let Some(response) = require_org_perm(deps, session, &scope, permission).await {
        return Err(*response);
    }
    Ok((org, cache, scope))
}

/// `GET /-/org/{org}/caches/{slug}` — a cache's read-only overview.
pub(crate) async fn cache_detail(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "overview").await
}

/// `GET /-/org/{org}/caches/{slug}/access` — cache identity and access policy.
pub(crate) async fn cache_access(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "access").await
}

/// Shows registry-owned retention relationships attached to a cache.
pub(crate) async fn cache_retention_subscriptions(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(
        deps,
        headers,
        started,
        org_slug,
        cache_slug,
        "retention-subscriptions",
    )
    .await
}

/// Shows population targets independently from retention and advertisement.
pub(crate) async fn cache_population_targets(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(
        deps,
        headers,
        started,
        org_slug,
        cache_slug,
        "population-targets",
    )
    .await
}

/// Shows manually managed retention roots and their lease heads.
pub(crate) async fn cache_manual_roots(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "manual-roots").await
}

/// Shows immutable placement-policy revisions for a cache.
pub(crate) async fn cache_placement_policies(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(
        deps,
        headers,
        started,
        org_slug,
        cache_slug,
        "placement-policies",
    )
    .await
}

/// Shows confirmed placement equivalences for a cache.
pub(crate) async fn cache_placement_equivalences(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(
        deps,
        headers,
        started,
        org_slug,
        cache_slug,
        "placement-equivalences",
    )
    .await
}

/// `GET /-/org/{org}/caches/{slug}/objects` — indexed cache objects.
pub(crate) async fn cache_objects(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "objects").await
}

/// `GET /-/org/{org}/caches/{slug}/signing-key` — signing identity.
pub(crate) async fn cache_signing_key(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "signing-key").await
}

/// Reviewed typed signing usage submitted from a cache settings page.
#[derive(serde::Deserialize)]
pub(crate) struct CacheSigningKeyForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    key_generation: String,
    #[serde(default)]
    signing_key_stable_id: String,
    #[serde(default)]
    signing_key_generation: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    expected_resource_version: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// Plans or applies the cache's exact narinfo signing-key generation usage.
pub(crate) async fn cache_signing_key_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CacheSigningKeyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    if let Err(response) = require_sudo(&session, &headers) {
        return *response;
    }
    let (org, cache, _) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::KeysManage,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, Scope::parse(&org.stable_id)) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !form.plan_id.is_empty() {
        return match deps
            .topology
            .apply_signing_key_usage(
                &bearer,
                form.plan_id.clone(),
                form.confirmation_hash,
                console_apply_idempotency_key(&form.plan_id),
            )
            .await
        {
            Ok(_) => {
                render_cache_detail(
                    &deps,
                    &session,
                    &org,
                    &cache,
                    true,
                    "signing-key",
                    Some("Signing-key usage updated."),
                    started,
                )
                .await
            }
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    let (key_id, generation) = if form.state == "active" {
        match form.key_generation.rsplit_once(':') {
            Some((key_id, generation)) => (key_id.to_string(), generation.to_string()),
            None => {
                return (StatusCode::BAD_REQUEST, "select a signing-key generation").into_response()
            }
        }
    } else if form.state == "detached" {
        (form.signing_key_stable_id, form.signing_key_generation)
    } else {
        return (StatusCode::BAD_REQUEST, "invalid signing usage state").into_response();
    };
    let generation = match generation.parse::<u64>() {
        Ok(generation) if generation > 0 => generation,
        _ => return (StatusCode::BAD_REQUEST, "invalid signing-key generation").into_response(),
    };
    match deps
        .topology
        .plan_signing_key_usage(
            &bearer,
            aos_proto_types::PlanSigningKeyUsageRequest {
                consumer_stable_id: cache.stable_id.clone(),
                purpose: "narinfo".to_string(),
                signing_key_stable_id: key_id,
                signing_key_generation: generation,
                state: form.state,
                expected_resource_version: form.expected_resource_version,
                idempotency_key: format!(
                    "console-plan-cache-signing-usage-{}",
                    uuid::Uuid::new_v4()
                ),
            },
        )
        .await
    {
        Ok(plan) => Html(console::signing_topology_plan_page(
            &session.email,
            "Change cache signing usage",
            &format!("/-/org/{org_slug}/caches/{cache_slug}/signing-key"),
            &session.csrf(),
            &plan,
            "usage",
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

/// `GET /-/org/{org}/caches/{slug}/operations` — cache operations.
pub(crate) async fn cache_operations(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "operations").await
}

/// `GET /-/org/{org}/caches/{slug}/garbage-collection` — collection policy and plans.
pub(crate) async fn cache_garbage_collection(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(
        deps,
        headers,
        started,
        org_slug,
        cache_slug,
        "garbage-collection",
    )
    .await
}

/// Shows one local garbage-collection history/work-queue view.
pub(crate) async fn cache_gc_section(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    active: &'static str,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, active).await
}

/// `GET /-/org/{org}/caches/{slug}/danger` — the **Danger** (delete) tab.
pub(crate) async fn cache_danger(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "danger").await
}

/// `GET /-/org/{org}/caches/{slug}/placements` — storage and replica topology.
pub(crate) async fn cache_placements(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "placements").await
}

/// Renders a cache placement creation form backed by organization bindings.
pub(crate) async fn cache_new_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let (org, _, _) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    match deps.db.list_storage_binding_read_summaries(org.id).await {
        Ok(bindings) => Html(console::new_placement_page(
            &session.email,
            "Add cache placement",
            &format!("/-/org/{org_slug}/caches/{cache_slug}/placements/plan-create"),
            &session.csrf(),
            &bindings,
            started,
        ))
        .into_response(),
        Err(error) => internal(error),
    }
}

/// Plans creation of one cache placement.
pub(crate) async fn cache_plan_create_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<PlacementCreateForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let spec = match form.spec() {
        Ok(spec) => spec,
        Err(response) => return response,
    };
    let (_, cache, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_create_placement(
            &bearer,
            TopologySurface::Cache(cache.slug),
            spec,
            format!("console-cache-plan-create-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Create cache placement",
            &format!("/-/org/{org_slug}/caches/{cache_slug}/placements/create"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies a reviewed cache placement creation.
pub(crate) async fn cache_create_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    cache_apply_basic_placement_plan(
        deps,
        headers,
        org_slug,
        cache_slug,
        form,
        PlacementPlanOperation::Create,
    )
    .await
}

#[derive(serde::Deserialize)]
pub(crate) struct PlacementPlanForm {
    #[serde(default)]
    csrf: String,
    expected_resource_version: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct PlacementApplyForm {
    #[serde(default)]
    csrf: String,
    plan_id: String,
    confirmation_hash: String,
}

/// Derives the browser's stable retry key from the immutable reviewed plan.
///
/// The value is deterministic so a refresh, double-submit, or retry after a
/// lost response replays the same apply instead of reserving the plan under a
/// fresh key. The plan identifier is opaque, actor-bound, and capped at 64
/// bytes by the retained-control store, keeping this key within its 128-byte
/// limit.
fn console_apply_idempotency_key(plan_id: &str) -> String {
    format!("console-apply-{plan_id}")
}

#[derive(serde::Deserialize)]
pub(crate) struct TopologyPlanForm {
    #[serde(default)]
    csrf: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct PlacementCreateForm {
    #[serde(default)]
    csrf: String,
    name: String,
    storage_binding_id: String,
    prefix: String,
    kind: String,
    desired_state: String,
    #[serde(default)]
    desired_read_enabled: Option<String>,
    read_order: i64,
    #[serde(default)]
    hash_range_start: Option<u32>,
    #[serde(default)]
    hash_range_end: Option<u32>,
    #[serde(default)]
    requires_conditional_writes: Option<String>,
}

impl PlacementCreateForm {
    fn spec(&self) -> Result<PlacementCreateSpec, Response> {
        let hash_range = match (self.hash_range_start, self.hash_range_end) {
            (Some(start), Some(end)) => Some((start, end)),
            (None, None) => None,
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "shard range requires both start and end",
                )
                    .into_response())
            }
        };
        Ok(PlacementCreateSpec {
            name: self.name.trim().to_string(),
            storage_binding_id: self.storage_binding_id.clone(),
            prefix: self.prefix.trim().to_string(),
            kind: self.kind.clone(),
            desired_state: self.desired_state.clone(),
            desired_read_enabled: self.desired_read_enabled.is_some(),
            read_order: self.read_order,
            hash_range,
            requires_conditional_writes: self.requires_conditional_writes.is_some(),
        })
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct PlacementUpdateForm {
    #[serde(default)]
    csrf: String,
    expected_resource_version: String,
    desired_state: String,
    #[serde(default)]
    desired_read_enabled: Option<String>,
    read_order: i64,
}

/// Plans promotion of one cache placement without changing authority.
pub(crate) async fn cache_plan_promote_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug, placement)): Path<(String, String, String)>,
    Form(form): Form<PlacementPlanForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, cache, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_promote_placement(
            &bearer,
            TopologySurface::Cache(cache.slug.clone()),
            placement.clone(),
            form.expected_resource_version,
            format!("console-cache-promote-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            &format!("Promote placement · {placement}"),
            &format!("/-/org/{org_slug}/caches/{cache_slug}/placements/{placement}/promote"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies one previously reviewed cache-placement promotion plan.
pub(crate) async fn cache_promote_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug, _placement)): Path<(String, String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, _, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .promote_placement(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(_) => Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/placements"))
            .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Plans replacement of a cache placement's mutable desired fields.
pub(crate) async fn cache_plan_update_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug, placement)): Path<(String, String, String)>,
    Form(form): Form<PlacementUpdateForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, cache, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_update_placement(
            &bearer,
            TopologySurface::Cache(cache.slug),
            placement.clone(),
            form.expected_resource_version,
            PlacementUpdateSpec {
                desired_state: form.desired_state,
                desired_read_enabled: form.desired_read_enabled.is_some(),
                read_order: form.read_order,
            },
            format!("console-cache-plan-update-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            &format!("Update cache placement · {placement}"),
            &format!(
                "/-/org/{org_slug}/caches/{cache_slug}/placements/{}/update",
                urlencode(&placement),
            ),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies a reviewed cache placement update.
pub(crate) async fn cache_update_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug, _placement)): Path<(String, String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    cache_apply_basic_placement_plan(
        deps,
        headers,
        org_slug,
        cache_slug,
        form,
        PlacementPlanOperation::Update,
    )
    .await
}

/// Plans cancellation of a cache's in-flight placement promotion.
pub(crate) async fn cache_plan_cancel_placement_promotion(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<TopologyPlanForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, cache, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_cancel_placement_promotion(
            &bearer,
            TopologySurface::Cache(cache.slug),
            format!("console-cache-plan-cancel-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Cancel cache placement promotion",
            &format!("/-/org/{org_slug}/caches/{cache_slug}/placements/cancel-promotion"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies a reviewed cache promotion cancellation.
pub(crate) async fn cache_cancel_placement_promotion(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    cache_apply_basic_placement_plan(
        deps,
        headers,
        org_slug,
        cache_slug,
        form,
        PlacementPlanOperation::CancelPromotion,
    )
    .await
}

async fn cache_apply_basic_placement_plan(
    deps: ConsoleDeps,
    headers: HeaderMap,
    org_slug: String,
    cache_slug: String,
    form: PlacementApplyForm,
    operation: PlacementPlanOperation,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, _, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_placement_plan(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            operation,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(()) => Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/placements"))
            .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

async fn cache_plan_placement_lifecycle(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: Instant,
    org_slug: String,
    cache_slug: String,
    placement: String,
    form: PlacementPlanForm,
    action: PlacementLifecycleAction,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, cache, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let operation = match action {
        PlacementLifecycleAction::Drain => "drain",
        PlacementLifecycleAction::Delete => "delete",
    };
    match deps
        .topology
        .plan_placement_lifecycle(
            &bearer,
            TopologySurface::Cache(cache.slug),
            placement.clone(),
            form.expected_resource_version,
            action,
            format!("console-cache-plan-{operation}-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            &format!(
                "{} cache placement · {placement}",
                operation_title(operation)
            ),
            &format!(
                "/-/org/{org_slug}/caches/{cache_slug}/placements/{}/{operation}",
                urlencode(&placement),
            ),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

async fn cache_apply_placement_lifecycle(
    deps: ConsoleDeps,
    headers: HeaderMap,
    org_slug: String,
    cache_slug: String,
    form: PlacementApplyForm,
    action: PlacementLifecycleAction,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, _, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_placement_lifecycle(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            action,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(()) => Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/placements"))
            .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

fn operation_title(operation: &str) -> &'static str {
    match operation {
        "drain" => "Drain",
        "delete" => "Delete",
        _ => "Change",
    }
}

macro_rules! cache_placement_lifecycle_handlers {
    ($plan:ident, $apply:ident, $action:expr) => {
        pub(crate) async fn $plan(
            deps: ConsoleDeps,
            headers: HeaderMap,
            RequestStart(started): RequestStart,
            Path((org_slug, cache_slug, placement)): Path<(String, String, String)>,
            Form(form): Form<PlacementPlanForm>,
        ) -> Response {
            cache_plan_placement_lifecycle(
                deps, headers, started, org_slug, cache_slug, placement, form, $action,
            )
            .await
        }

        pub(crate) async fn $apply(
            deps: ConsoleDeps,
            headers: HeaderMap,
            Path((org_slug, cache_slug, _placement)): Path<(String, String, String)>,
            Form(form): Form<PlacementApplyForm>,
        ) -> Response {
            cache_apply_placement_lifecycle(deps, headers, org_slug, cache_slug, form, $action)
                .await
        }
    };
}

cache_placement_lifecycle_handlers!(
    cache_plan_drain_placement,
    cache_drain_placement,
    PlacementLifecycleAction::Drain
);
cache_placement_lifecycle_handlers!(
    cache_plan_delete_placement,
    cache_delete_placement,
    PlacementLifecycleAction::Delete
);

/// Plans transition of a cache to an explicitly read-only topology.
pub(crate) async fn cache_plan_remove_write_authority(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<TopologyPlanForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, cache, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_remove_write_authority(&bearer, TopologySurface::Cache(cache.slug))
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Remove cache write authority",
            &format!("/-/org/{org_slug}/caches/{cache_slug}/placements/remove-write-authority"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies a reviewed transition of a cache to read-only topology.
pub(crate) async fn cache_remove_write_authority(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, cache, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::PlacementManage,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .remove_write_authority(
            &bearer,
            TopologySurface::Cache(cache.slug),
            form.plan_id.clone(),
            form.confirmation_hash,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(_) => Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/placements"))
            .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Shows all simultaneous delivery routes for a cache.
pub(crate) async fn cache_delivery(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(
        deps,
        headers,
        started,
        org_slug,
        cache_slug,
        "delivery-routes",
    )
    .await
}

/// Shows exact canonical-audience selections separately from route inventory.
pub(crate) async fn cache_canonical_audiences(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(
        deps,
        headers,
        started,
        org_slug,
        cache_slug,
        "canonical-audiences",
    )
    .await
}

/// Shared body for the cache settings tabs: require a session + read on the org,
/// load the `(org, cache)` pair, resolve admin authority, then render the
/// `active` section within the cache settings chrome.
async fn cache_tab(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: Instant,
    org_slug: String,
    cache_slug: String,
    active: &str,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let (page, local_permission) = match active {
        "canonical-audiences" => (Some(CachePage::DeliveryRoutes), Some(Permission::RouteRead)),
        "gc-plans" => (
            Some(CachePage::GarbageCollection),
            Some(Permission::CacheGcPlan),
        ),
        "gc-runs" | "gc-jobs" => (
            Some(CachePage::GarbageCollection),
            Some(Permission::CacheGcExecute),
        ),
        _ => (CachePage::parse(active), None),
    };
    let Some(page) = page else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let required = local_permission.unwrap_or_else(|| {
        CACHE_PAGES
            .iter()
            .find(|spec| spec.key == page)
            .map_or(Permission::Read, |spec| spec.permission)
    });
    let (org, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let scope = Scope::parse(&cache.scope_key);
    if !session.allows(&deps.db, required, &scope).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let can_admin = session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await;
    render_cache_detail(
        &deps, &session, &org, &cache, can_admin, active, None, started,
    )
    .await
}

/// Plans a version-checked cache identity and protocol-policy update.
pub(crate) async fn cache_plan_update(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CacheUpdateForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let (_, cache, _) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::RegistryConfigure,
    )
    .await
    {
        Ok(cache) => cache,
        Err(resp) => return resp,
    };
    let Some(visibility) = cache_visibility(&form.visibility) else {
        return (StatusCode::BAD_REQUEST, "invalid visibility").into_response();
    };
    let name = if form.name.trim().is_empty() {
        cache.name.clone()
    } else {
        form.name.trim().to_string()
    };
    let priority = match form.nix_priority.trim().parse::<u32>() {
        Ok(priority) => priority,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid Nix priority").into_response(),
    };
    let compression = match form.compression.trim() {
        "" => cache.compression.clone(),
        c @ ("zstd" | "xz" | "none") => c.to_string(),
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid compression '{other}'"),
            )
                .into_response()
        }
    };
    let scope = Scope::parse(&cache.scope_key);
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let request = aos_proto_types::PlanBinaryCacheMutationRequest {
        stable_id: cache.stable_id,
        desired: Some(aos_proto_types::BinaryCacheSpec {
            slug: String::new(),
            name,
            owner_scope_key: String::new(),
            visibility: visibility.to_string(),
            nix_priority: priority,
            compression,
            want_mass_query: form.want_mass_query.is_some(),
        }),
        update_mask: vec![
            "name".to_string(),
            "visibility".to_string(),
            "nix_priority".to_string(),
            "compression".to_string(),
            "want_mass_query".to_string(),
        ],
        expected_resource_version: form.expected_resource_version,
        idempotency_key: format!("console-cache-plan-update-{}", uuid::Uuid::new_v4()),
    };
    match deps
        .topology
        .plan_update_binary_cache(&bearer, request)
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Update binary-cache policy",
            &format!("/-/org/{org_slug}/caches/{cache_slug}/access/update"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

/// Applies a reviewed cache identity and protocol-policy update.
pub(crate) async fn cache_update(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, _, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::RegistryConfigure,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_update_binary_cache(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(()) => {
            Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/access")).into_response()
        }
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

/// Plans dependency-guarded deletion of one binary-cache identity.
pub(crate) async fn cache_plan_delete(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<DeleteByIdForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let (_, cache, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::IamAdmin,
    )
    .await
    {
        Ok(cache) => cache,
        Err(resp) => return resp,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_delete_binary_cache(&bearer, cache.stable_id, cache.resource_version.to_string())
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Delete binary cache",
            &format!("/-/org/{org_slug}/caches/{cache_slug}/danger/delete"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

/// Applies a reviewed dependency-guarded binary-cache deletion.
pub(crate) async fn cache_delete(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let (_, _, scope) = match cache_in_org_with_permission(
        &deps,
        &session,
        &org_slug,
        &cache_slug,
        Permission::IamAdmin,
    )
    .await
    {
        Ok(cache) => cache,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_delete_binary_cache(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(true) => Redirect::to(&format!("/-/org/{org_slug}/caches")).into_response(),
        Ok(false) => (StatusCode::CONFLICT, "binary cache was not deleted").into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

/// Why a membership grant or role change was refused by a console handler.
enum MembershipReject {
    /// The grant would exceed the actor's own authority (H1 escalation).
    Forbidden(String),
    /// Demoting the sole remaining owner would leave the org ownerless.
    LastOwner,
}

impl IntoResponse for MembershipReject {
    fn into_response(self) -> Response {
        match self {
            MembershipReject::Forbidden(msg) => (StatusCode::FORBIDDEN, msg).into_response(),
            MembershipReject::LastOwner => (
                StatusCode::CONFLICT,
                "cannot demote the last owner of an organization",
            )
                .into_response(),
        }
    }
}

/// Checks the membership-control privilege ceiling for a proposed grant.
///
/// # Errors
///
/// Returns an error on database failure.
async fn membership_grant_allowed(
    db: &Database,
    actor: &Principal,
    target: &Principal,
    scope: &Scope,
    role: Role,
) -> anyhow::Result<Result<(), MembershipReject>> {
    let Some(context) = db.authorization_context(scope.as_str()).await? else {
        return Ok(Err(MembershipReject::Forbidden(
            "authorization scope does not exist".to_string(),
        )));
    };
    let actor_rank = db
        .effective_scopes(*actor)
        .await?
        .into_iter()
        .filter(|(grant_scope, _)| context.is_covered_by(grant_scope))
        .map(|(_, r)| r.rank())
        .max()
        .unwrap_or(0);
    if role.rank() > actor_rank {
        return Ok(Err(MembershipReject::Forbidden(format!(
            "insufficient privilege to grant '{}'",
            role.as_str()
        ))));
    }
    if role == Role::Owner && actor_rank < Role::Owner.rank() {
        return Ok(Err(MembershipReject::Forbidden(
            "only an owner may grant 'owner'".to_string(),
        )));
    }
    if actor == target && role.rank() > actor_rank {
        return Ok(Err(MembershipReject::Forbidden(
            "a principal may not promote itself".to_string(),
        )));
    }
    Ok(Ok(()))
}

/// `POST /-/org/{org}/members` form: invite an email at a role.
#[derive(serde::Deserialize)]
pub(crate) struct InviteForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// `POST /-/org/{org}/members/invitations` — plan or create an invitation.
pub(crate) async fn org_invite_member(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    Form(form): Form<InviteForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope.clone()) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !form.plan_id.is_empty() {
        return match deps
            .topology
            .apply_invitation(
                &bearer,
                form.plan_id.clone(),
                form.confirmation_hash,
                console_apply_idempotency_key(&form.plan_id),
            )
            .await
        {
            Ok(created) => {
                let Some(invitation) = created.invitation else {
                    return internal(anyhow::anyhow!("invitation response omitted the resource"));
                };
                let link = format!(
                    "{}/-/org/{}/invitations/accept?token={}",
                    deps.external_url.trim_end_matches('/'),
                    org_slug,
                    created.secret,
                );
                let content = crate::email::invite_email(
                    console::brand(),
                    &org_slug,
                    &invitation.role,
                    &link,
                );
                let delivery_error = deps
                    .mailer
                    .send_email(&invitation.email, &content)
                    .await
                    .err()
                    .map(|error| format!("{error:#}"));
                Html(console::invitation_created_page(
                    &session.email,
                    &org_slug,
                    &invitation,
                    &link,
                    delivery_error.as_deref(),
                    started,
                ))
                .into_response()
            }
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    let Some(role) = Role::parse(&form.role) else {
        return (StatusCode::BAD_REQUEST, "unknown role").into_response();
    };
    let email = form.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return (StatusCode::BAD_REQUEST, "invalid email").into_response();
    }
    let result = async {
        let plan = deps
            .topology
            .plan_invitation(
                &bearer,
                aos_proto_types::PlanCreateInvitationRequest {
                    org_slug: org_slug.clone(),
                    email,
                    scope: scope.as_str().to_string(),
                    role: role.as_str().to_string(),
                    ttl_secs: 0,
                    expected_resource_version: String::new(),
                    idempotency_key: format!("console-plan-invite-member-{}", uuid::Uuid::new_v4()),
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok::<_, anyhow::Error>(plan)
    }
    .await;
    match result {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Invite organization member",
            &format!("/-/org/{org_slug}/members/invitations"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(err) => internal(err),
    }
}

/// Form for reviewing and applying an invitation cancellation.
#[derive(serde::Deserialize)]
pub(crate) struct CancelInvitationForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    if_version: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// `POST /-/org/{org}/members/invitations/{id}/cancel` — cancel an invite.
pub(crate) async fn cancel_invitation(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, invitation_id)): Path<(String, i64)>,
    Form(form): Form<CancelInvitationForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    if let Err(response) = require_sudo(&session, &headers) {
        return *response;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !form.plan_id.is_empty() {
        return match deps
            .topology
            .apply_invitation_cancellation(
                &bearer,
                form.plan_id.clone(),
                form.confirmation_hash,
                console_apply_idempotency_key(&form.plan_id),
            )
            .await
        {
            Ok(_) => Redirect::to(&format!("/-/org/{org_slug}/members")).into_response(),
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    let plan = deps
        .topology
        .plan_invitation_cancellation(
            &bearer,
            aos_proto_types::PlanCancelInvitationRequest {
                org_slug: org_slug.clone(),
                invitation_id,
                expected_resource_version: form.if_version,
                idempotency_key: format!("console-plan-cancel-invitation-{}", uuid::Uuid::new_v4()),
            },
        )
        .await;
    match plan {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Cancel organization invitation",
            &format!("/-/org/{org_slug}/members/invitations/{invitation_id}/cancel"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

/// Query carried by the invitation acceptance link.
#[derive(serde::Deserialize)]
pub(crate) struct InvitationAcceptQuery {
    #[serde(default)]
    token: Option<String>,
}

/// CSRF-protected invitation acceptance form.
#[derive(serde::Deserialize)]
pub(crate) struct InvitationAcceptForm {
    #[serde(default)]
    csrf: String,
}

const INVITATION_HANDOFF_COOKIE: &str = "__Host-aos_invitation";
const INVITATION_HANDOFF_TTL_SECS: i64 = 30 * 60;

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&prefix).map(str::to_string))
}

fn invitation_handoff_cookie(secret: &str) -> String {
    format!(
        "{INVITATION_HANDOFF_COOKIE}={secret}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={INVITATION_HANDOFF_TTL_SECS}"
    )
}

fn clear_invitation_handoff_cookie() -> String {
    format!("{INVITATION_HANDOFF_COOKIE}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

fn sensitive_browser_response(mut response: Response, set_cookie: Option<&str>) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Some(cookie) = set_cookie {
        match HeaderValue::from_str(cookie) {
            Ok(value) => {
                headers.append(header::SET_COOKIE, value);
            }
            Err(error) => return internal(error.into()),
        }
    }
    response
}

/// `GET /-/org/{org}/invitations/accept` — review an invitation ceremony.
pub(crate) async fn invitation_acceptance(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    Query(query): Query<InvitationAcceptQuery>,
) -> Response {
    let clean_path = format!("/-/org/{org_slug}/invitations/accept");
    if let Some(token) = query.token.as_deref().filter(|token| !token.is_empty()) {
        if !crate::auth::token::is_invitation_token(token) {
            return sensitive_browser_response(
                (StatusCode::BAD_REQUEST, "invalid invitation credential").into_response(),
                None,
            );
        }
        let response = Redirect::to(&clean_path).into_response();
        return sensitive_browser_response(response, Some(&invitation_handoff_cookie(token)));
    }
    let session = match require_session_with_return(&deps, &headers, Some(&clean_path)).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if cookie_value(&headers, INVITATION_HANDOFF_COOKIE).is_none() {
        return sensitive_browser_response(
            (
                StatusCode::BAD_REQUEST,
                "invitation handoff is missing or expired",
            )
                .into_response(),
            None,
        );
    }
    sensitive_browser_response(
        Html(console::invitation_acceptance_page(
            &session.email,
            &org_slug,
            &session.csrf(),
            started,
        ))
        .into_response(),
        None,
    )
}

/// `POST /-/org/{org}/invitations/accept` — atomically accept and join.
pub(crate) async fn accept_invitation(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<InvitationAcceptForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(secret) = cookie_value(&headers, INVITATION_HANDOFF_COOKIE) else {
        return (
            StatusCode::BAD_REQUEST,
            "invitation handoff is missing or expired",
        )
            .into_response();
    };
    let bearer = match session.topology_bearer(&deps, Scope::root()) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .accept_invitation(
            &bearer,
            aos_proto_types::AcceptInvitationRequest {
                org_slug: org_slug.clone(),
                secret,
            },
        )
        .await
    {
        Ok(_) => sensitive_browser_response(
            Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
            Some(&clear_invitation_handoff_cookie()),
        ),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

/// Resolves the public API reference for an already-materialized principal.
async fn membership_subject_ref(
    db: &Database,
    kind: crate::domain::PrincipalKind,
    id: i64,
) -> anyhow::Result<String> {
    match kind {
        crate::domain::PrincipalKind::User => db
            .user_email(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("membership user {id} no longer exists")),
        crate::domain::PrincipalKind::ServiceAccount => db
            .service_account_reference(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("membership service account {id} no longer exists")),
    }
}

/// Member-removal form for a resource-scoped principal action.
#[derive(serde::Deserialize)]
pub(crate) struct RemoveForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// Plans or applies removal of one direct organization membership.
pub(crate) async fn org_remove_member(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, principal_ref)): Path<(String, String)>,
    Form(form): Form<RemoveForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    let bearer = match session.topology_bearer(&deps, scope.clone()) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !form.plan_id.is_empty() {
        return match deps
            .topology
            .apply_membership(
                &bearer,
                form.plan_id.clone(),
                form.confirmation_hash,
                console_apply_idempotency_key(&form.plan_id),
            )
            .await
        {
            Ok(_) => Redirect::to(&format!("/-/org/{org_slug}/members")).into_response(),
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    let Some((kind_raw, id_raw)) = principal_ref.split_once(':') else {
        return (StatusCode::BAD_REQUEST, "invalid principal reference").into_response();
    };
    let Some(kind) = crate::domain::PrincipalKind::parse(kind_raw) else {
        return (StatusCode::BAD_REQUEST, "unknown principal kind").into_response();
    };
    let Ok(principal_id) = id_raw.parse::<i64>() else {
        return (StatusCode::BAD_REQUEST, "invalid principal reference").into_response();
    };
    let result = async {
        let members = deps.db.list_members_of_scope(scope.as_str()).await?;
        let owners: Vec<_> = members.iter().filter(|(_, _, r)| r == "owner").collect();
        let target_is_owner = members
            .iter()
            .any(|(k, id, r)| k == kind_raw && *id == principal_id && r == "owner");
        if target_is_owner && owners.len() <= 1 {
            return Ok(Err(()));
        }
        let subject_ref = membership_subject_ref(&deps.db, kind, principal_id).await?;
        let current = deps
            .topology
            .membership(
                &bearer,
                aos_proto_types::GetMembershipRequest {
                    principal_kind: kind.as_str().to_string(),
                    principal_ref: subject_ref.clone(),
                    scope: scope.as_str().to_string(),
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let plan = deps
            .topology
            .plan_membership(
                &bearer,
                aos_proto_types::PlanSetMembershipRequest {
                    principal_kind: kind.as_str().to_string(),
                    principal_ref: subject_ref,
                    scope: scope.as_str().to_string(),
                    role: String::new(),
                    expected_resource_version: current.resource_version,
                    idempotency_key: format!("console-plan-remove-member-{}", uuid::Uuid::new_v4()),
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok::<Result<crate::web::console::ports::ReviewedPlan, ()>, anyhow::Error>(Ok(plan))
    }
    .await;
    match result {
        Ok(Ok(plan)) => Html(console::topology_plan_page(
            &session.email,
            "Remove organization member",
            &format!("/-/org/{org_slug}/members/{principal_ref}/remove"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Ok(Err(())) => (
            StatusCode::CONFLICT,
            "cannot remove the last owner of an organization",
        )
            .into_response(),
        Err(err) if crate::db::is_last_owner_error(&err) => (
            StatusCode::CONFLICT,
            "cannot remove the last owner of an organization",
        )
            .into_response(),
        Err(err) => internal(err),
    }
}

/// Member-role form for a resource-scoped principal action.
#[derive(serde::Deserialize)]
pub(crate) struct RoleForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// Plans or applies replacement of one direct organization membership.
pub(crate) async fn org_member_role(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, principal_ref)): Path<(String, String)>,
    Form(form): Form<RoleForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    let bearer = match session.topology_bearer(&deps, scope.clone()) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !form.plan_id.is_empty() {
        return match deps
            .topology
            .apply_membership(
                &bearer,
                form.plan_id.clone(),
                form.confirmation_hash,
                console_apply_idempotency_key(&form.plan_id),
            )
            .await
        {
            Ok(_) => Redirect::to(&format!("/-/org/{org_slug}/members")).into_response(),
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    let Some((kind_raw, id_raw)) = principal_ref.split_once(':') else {
        return (StatusCode::BAD_REQUEST, "invalid principal reference").into_response();
    };
    let Some(kind) = crate::domain::PrincipalKind::parse(kind_raw) else {
        return (StatusCode::BAD_REQUEST, "unknown principal kind").into_response();
    };
    let Ok(principal_id) = id_raw.parse::<i64>() else {
        return (StatusCode::BAD_REQUEST, "invalid principal reference").into_response();
    };
    let Some(role) = Role::parse(&form.role) else {
        return (StatusCode::BAD_REQUEST, "unknown role").into_response();
    };
    let target = Principal {
        kind,
        id: principal_id,
    };
    let result = async {
        if let Err(reject) =
            membership_grant_allowed(&deps.db, &session.principal(), &target, &scope, role).await?
        {
            return Ok(Err(reject));
        }
        let members = deps.db.list_members_of_scope(scope.as_str()).await?;
        let owners = members.iter().filter(|(_, _, r)| r == "owner").count();
        let target_is_last_owner = role != Role::Owner
            && owners <= 1
            && members
                .iter()
                .any(|(k, id, r)| k == kind_raw && *id == principal_id && r == "owner");
        if target_is_last_owner {
            return Ok(Err(MembershipReject::LastOwner));
        }
        let subject_ref = membership_subject_ref(&deps.db, kind, principal_id).await?;
        let current = deps
            .topology
            .membership(
                &bearer,
                aos_proto_types::GetMembershipRequest {
                    principal_kind: kind.as_str().to_string(),
                    principal_ref: subject_ref.clone(),
                    scope: scope.as_str().to_string(),
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let plan = deps
            .topology
            .plan_membership(
                &bearer,
                aos_proto_types::PlanSetMembershipRequest {
                    principal_kind: kind.as_str().to_string(),
                    principal_ref: subject_ref,
                    scope: scope.as_str().to_string(),
                    role: role.as_str().to_string(),
                    expected_resource_version: current.resource_version,
                    idempotency_key: format!(
                        "console-plan-set-member-role-{}",
                        uuid::Uuid::new_v4()
                    ),
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok::<Result<crate::web::console::ports::ReviewedPlan, MembershipReject>, anyhow::Error>(Ok(
            plan,
        ))
    }
    .await;
    match result {
        Ok(Ok(plan)) => Html(console::topology_plan_page(
            &session.email,
            "Change organization member role",
            &format!("/-/org/{org_slug}/members/{principal_ref}/role"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Ok(Err(reject)) => reject.into_response(),
        Err(err) if crate::db::is_last_owner_error(&err) => {
            MembershipReject::LastOwner.into_response()
        }
        Err(err) => internal(err),
    }
}

// -- create organization ----------------------------------------------------

/// `GET /new` — the create-organization form.
pub(crate) async fn new_org_form(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    match may_create_org(&deps.db, &session).await {
        Ok(true) => Html(console::new_org_page(
            &session.email,
            &session.csrf(),
            None,
            started,
        ))
        .into_response(),
        Ok(false) => (
            StatusCode::FORBIDDEN,
            "org creation is invite-only on this instance",
        )
            .into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /new` form: the new org's slug and display name.
#[derive(serde::Deserialize)]
pub(crate) struct NewOrgForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    slug: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// `POST /new` — plan or apply organization creation and its initial owner grant.
pub(crate) async fn new_org_submit(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<NewOrgForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if !form.plan_id.is_empty() {
        let bearer = match session.topology_bearer(&deps, Scope::root()) {
            Ok(bearer) => bearer,
            Err(error) => return internal(error),
        };
        return match deps
            .topology
            .apply_create_organization(
                &bearer,
                form.plan_id.clone(),
                form.confirmation_hash,
                console_apply_idempotency_key(&form.plan_id),
            )
            .await
        {
            Ok(response) => match response.organization {
                Some(org) => Redirect::to(&format!("/-/org/{}", org.slug)).into_response(),
                None => internal(anyhow::anyhow!(
                    "organization apply response omitted organization"
                )),
            },
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    match may_create_org(&deps.db, &session).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                "org creation is invite-only on this instance",
            )
                .into_response()
        }
        Err(err) => return internal(err),
    }
    let slug = form.slug.trim();
    let name = form.name.trim();
    let reject = |message: &str| {
        Html(console::new_org_page(
            &session.email,
            &session.csrf(),
            Some(message),
            started,
        ))
        .into_response()
    };
    if slug.is_empty() || name.is_empty() {
        return reject("Enter both a slug and a display name.");
    }
    if let Err(err) = iam::validate_org_slug(slug) {
        return reject(&format!(
            "The slug may contain only lowercase letters, digits, '-', and '_', and must not be a reserved name ({err})."
        ));
    }
    let principal = session.principal();
    let rl_key = format!("{}:{}", principal.kind.as_str(), principal.id);
    if let crate::ratelimit::RateDecision::Limited { retry_after } = deps
        .ratelimit
        .check(
            crate::ratelimit::RateClass::CreateOrg,
            &rl_key,
            crate::clock::now_unix_secs(),
        )
        .await
    {
        return too_many_requests(retry_after);
    }
    match deps.db.count_user_owned_orgs(principal.id).await {
        Ok(owned) if owned >= crate::ratelimit::MAX_ORGS_PER_OWNER => {
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "owned-org limit reached ({} max); contact an instance admin",
                    crate::ratelimit::MAX_ORGS_PER_OWNER
                ),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(err) => return internal(err),
    }
    let bearer = match session.topology_bearer(&deps, Scope::root()) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_create_organization(
            &bearer,
            aos_proto_types::PlanCreateOrganizationRequest {
                slug: slug.to_string(),
                display_name: name.to_string(),
                idempotency_key: format!("console-plan-create-org-{}", uuid::Uuid::new_v4()),
                expected_resource_version: String::new(),
            },
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Create organization",
            "/-/orgs/new",
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => reject(&error.to_string()),
    }
}

/// A `429 Too Many Requests` response carrying a `Retry-After` header.
fn too_many_requests(retry_after: i64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.max(1).to_string())],
        "rate limit exceeded",
    )
        .into_response()
}

// -- create project / binding / registry under an org -----------------------

/// CSRF form for a resource-scoped delete action.
#[derive(serde::Deserialize)]
pub(crate) struct DeleteByIdForm {
    #[serde(default)]
    csrf: String,
}

/// Plans deletion of an unused storage binding addressed by its resource URL.
pub(crate) async fn org_plan_delete_binding(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, binding_id)): Path<(String, String)>,
    Form(form): Form<DeleteByIdForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingManage).await
    {
        return *deny;
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let Some(binding) = deps
            .db
            .storage_binding_by_stable_id(&binding_id)
            .await?
            .filter(|binding| binding.org_id == Some(org.id))
        else {
            return Ok(Some(Err("no such binding")));
        };
        let bearer = session.topology_bearer(&deps, Scope::parse(&org.stable_id))?;
        let plan = deps
            .topology
            .plan_delete_storage_binding(
                &bearer,
                binding.stable_id.clone(),
                binding.resource_version.to_string(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok::<_, anyhow::Error>(Some(Ok(plan)))
    }
    .await;
    match result {
        Ok(Some(Ok(plan))) => Html(console::topology_plan_page(
            &session.email,
            "Delete storage binding",
            &format!("/-/org/{org_slug}/storage-bindings/{binding_id}/delete"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Ok(Some(Err(msg))) => (StatusCode::CONFLICT, msg).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Applies a reviewed storage-binding deletion.
pub(crate) async fn org_delete_binding(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, binding_id)): Path<(String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(response) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingManage).await
    {
        return *response;
    }
    let Some(org) = deps.db.org_by_slug(&org_slug).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let binding_exists = deps
        .db
        .storage_binding_by_stable_id(&binding_id)
        .await
        .map(|binding| binding.is_some_and(|binding| binding.org_id == Some(org.id)));
    match binding_exists {
        Ok(true) => {}
        Ok(false) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return internal(error),
    }
    let bearer = match session.topology_bearer(&deps, Scope::parse(&org.stable_id)) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_delete_storage_binding(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(_) => Redirect::to(&format!("/-/org/{org_slug}/storage-bindings")).into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// `POST /-/org/{org}/storage-bindings/plan-create` form.
#[derive(serde::Deserialize)]
pub(crate) struct NewBindingForm {
    #[serde(default)]
    csrf: String,
    name: String,
    /// Backend kind (`local_fs`, `s3`, or `r2`); defaults to `local_fs`.
    #[serde(default)]
    kind: String,
    /// Host path for `local_fs`; bucket (optionally `bucket/sub-prefix`) for
    /// `s3`/`r2`.
    root: String,
    /// Endpoint origin URL for an `s3`/`r2` binding.
    #[serde(default)]
    endpoint: String,
    /// Signing region for an `s3`/`r2` binding (defaults to `auto`).
    #[serde(default)]
    region: String,
    /// Access mode for an `s3`/`r2` binding: `private` (default) or `public`.
    #[serde(default)]
    access: String,
}

fn storage_endpoint_from_origin(raw: &str) -> Result<aos_proto_types::StorageEndpoint, String> {
    let parsed =
        url::Url::parse(raw.trim()).map_err(|error| format!("invalid endpoint: {error}"))?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "endpoint must be an HTTPS origin without credentials, path, query, or fragment".into(),
        );
    }
    let host = match parsed.host() {
        Some(url::Host::Domain(name)) => {
            aos_proto_types::storage_endpoint::Host::DnsName(name.to_string())
        }
        Some(url::Host::Ipv4(address)) => {
            aos_proto_types::storage_endpoint::Host::Ipv4(address.octets().to_vec())
        }
        Some(url::Host::Ipv6(address)) => {
            aos_proto_types::storage_endpoint::Host::Ipv6(address.octets().to_vec())
        }
        None => return Err("endpoint host is required".into()),
    };
    Ok(aos_proto_types::StorageEndpoint {
        scheme: "https".into(),
        host: Some(host),
        port: u32::from(parsed.port_or_known_default().unwrap_or(443)),
    })
}

/// Plans a storage-binding creation for explicit operator review.
pub(crate) async fn org_plan_create_binding(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    Form(form): Form<NewBindingForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingManage).await
    {
        return *deny;
    }
    let name = form.name.trim();
    let root = form.root.trim();
    if name.is_empty() || root.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "binding name and root are required",
        )
            .into_response();
    }
    let kind = form.kind.trim();
    let kind = if kind.is_empty() { "local_fs" } else { kind };
    let provider = match kind {
        "local_fs" => aos_proto_types::storage_binding_spec::Provider::LocalFilesystem(
            aos_proto_types::LocalFilesystemStorageProvider {
                root_path: root.to_string(),
            },
        ),
        "s3" | "r2" => {
            let endpoint = match storage_endpoint_from_origin(&form.endpoint) {
                Ok(endpoint) => endpoint,
                Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
            };
            let (bucket, prefix) = root.split_once('/').unwrap_or((root, ""));
            let signing_region = match form.region.trim() {
                "" => "auto".to_string(),
                region => region.to_string(),
            };
            let access_mode = match form.access.trim() {
                "" => "private".to_string(),
                access => access.to_string(),
            };
            if kind == "s3" {
                aos_proto_types::storage_binding_spec::Provider::S3(
                    aos_proto_types::S3StorageProvider {
                        bucket: bucket.to_string(),
                        prefix: prefix.to_string(),
                        endpoint: Some(endpoint),
                        signing_region,
                        access_mode,
                    },
                )
            } else {
                aos_proto_types::storage_binding_spec::Provider::R2(
                    aos_proto_types::R2StorageProvider {
                        bucket: bucket.to_string(),
                        prefix: prefix.to_string(),
                        endpoint: Some(endpoint),
                        signing_region,
                        access_mode,
                    },
                )
            }
        }
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("unknown storage binding provider '{other}'"),
            )
                .into_response()
        }
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let bearer = session.topology_bearer(&deps, Scope::parse(&org.stable_id))?;
        let stable_id = uuid::Uuid::new_v4().simple().to_string();
        let plan = deps
            .topology
            .plan_create_storage_binding(
                &bearer,
                aos_proto_types::PlanStorageBindingMutationRequest {
                    stable_id,
                    owner_scope_key: org.stable_id,
                    spec: Some(aos_proto_types::StorageBindingSpec {
                        name: name.to_string(),
                        provider: Some(provider),
                    }),
                    expected_resource_version: String::new(),
                    idempotency_key: format!(
                        "console-plan-create-binding-{}",
                        uuid::Uuid::new_v4()
                    ),
                    update_mask: Vec::new(),
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok::<_, anyhow::Error>(Some(plan))
    }
    .await;
    match result {
        Ok(Some(plan)) => Html(console::topology_plan_page(
            &session.email,
            "Create storage binding",
            &format!("/-/org/{org_slug}/storage-bindings/create"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, format!("{error:#}")).into_response(),
    }
}

/// Applies a reviewed storage-binding creation.
pub(crate) async fn org_apply_create_binding(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(response) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingManage).await
    {
        return *response;
    }
    if deps
        .db
        .org_by_slug(&org_slug)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_create_storage_binding(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(_) => Redirect::to(&format!("/-/org/{org_slug}/storage-bindings")).into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Shows one storage binding addressed only by stable API identity.
pub(crate) async fn org_binding(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, binding_id)): Path<(String, String)>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingRead).await
    {
        return *deny;
    }
    org_binding_view(
        &deps,
        &session,
        &org_slug,
        &binding_id,
        None,
        "overview",
        started,
    )
    .await
}

/// Shows one declared storage-binding subsection.
pub(crate) async fn org_binding_section(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, binding_id)): Path<(String, String)>,
    active: &'static str,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let scope = organization_scope(&deps.db, &org_slug).await;
    let required = match active {
        "credentials" | "write-revisions" | "danger" => Permission::StorageBindingManage,
        "consumer-grants" => Permission::StorageBindingGrant,
        "placements" => Permission::PlacementRead,
        "storage-gateways" => Permission::StorageGatewayRead,
        "overview" => Permission::StorageBindingRead,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if let Some(deny) = require_org_perm(&deps, &session, &scope, required).await {
        return *deny;
    }
    org_binding_view(
        &deps,
        &session,
        &org_slug,
        &binding_id,
        None,
        active,
        started,
    )
    .await
}

/// Renders one org storage-binding section, or `404` for a foreign binding.
///
/// The GET pages and POST actions share this renderer so authorization,
/// navigation, and topology context remain consistent.
async fn org_binding_view(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    binding_id: &str,
    notice: Option<&str>,
    active: &str,
    started: Instant,
) -> Response {
    let scope = organization_scope(&deps.db, org_slug).await;
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let org = match deps.db.org_by_slug(org_slug).await {
        Ok(Some(o)) => o,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    let binding = match deps
        .db
        .storage_binding_read_detail_by_stable_id(binding_id)
        .await
    {
        Ok(Some(b)) if b.org_id == Some(org.id) => b,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    let can_manage_binding = session
        .allows(&deps.db, Permission::StorageBindingManage, &scope)
        .await;
    let managed_binding = if can_manage_binding {
        match deps.db.storage_binding_by_stable_id(binding_id).await {
            Ok(Some(record)) if record.org_id == Some(org.id) => Some(record),
            Ok(_) => return StatusCode::NOT_FOUND.into_response(),
            Err(error) => return internal(error),
        }
    } else {
        None
    };
    let credentials = if active == "credentials" && can_manage_binding {
        match deps
            .db
            .list_current_storage_binding_credentials(binding.id)
            .await
        {
            Ok(credentials) => credentials,
            Err(err) => return internal(err),
        }
    } else {
        Vec::new()
    };
    let revision_records = if active == "write-revisions" && can_manage_binding {
        match deps
            .db
            .list_storage_binding_write_revisions(binding.id)
            .await
        {
            Ok(revisions) => revisions,
            Err(err) => return internal(err),
        }
    } else {
        Vec::new()
    };
    let mut write_revisions = Vec::with_capacity(revision_records.len());
    for revision in revision_records {
        let observation = match deps
            .db
            .storage_binding_write_observation(binding.id, revision.revision)
            .await
        {
            Ok(observation) => observation,
            Err(err) => return internal(err),
        };
        write_revisions.push((revision, observation));
    }
    let grant_records = if active == "consumer-grants" {
        match deps
            .db
            .list_consumer_scope_grants(crate::db::GrantResource::StorageBinding {
                id: binding.id,
                stable_id: &binding.stable_id,
            })
            .await
        {
            Ok(grants) => grants,
            Err(err) => return internal(err),
        }
    } else {
        Vec::new()
    };
    let mut grants = Vec::with_capacity(grant_records.len());
    for grant in grant_records {
        let pins = match deps
            .db
            .consumer_scope_grant_pin_impacts(
                crate::db::GrantResource::StorageBinding {
                    id: binding.id,
                    stable_id: &binding.stable_id,
                },
                &grant.consumer_scope_key,
            )
            .await
        {
            Ok(pins) => pins,
            Err(err) => return internal(err),
        };
        grants.push((grant, pins));
    }
    Html(console::org_binding_page(
        &session.email,
        org_slug,
        &session.csrf(),
        &binding,
        managed_binding.as_ref(),
        &credentials,
        &write_revisions,
        &grants,
        can_manage_binding,
        notice,
        active,
        &navigation,
        started,
    ))
    .into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct BindingCredentialPlanForm {
    #[serde(default)]
    csrf: String,
    purpose: String,
    secret_version_ref: String,
    credential_fingerprint: String,
    #[serde(default)]
    expected_resource_version: String,
    #[serde(default)]
    expected_current_generation: i64,
}

#[derive(serde::Deserialize)]
pub(crate) struct BindingGrantPlanForm {
    #[serde(default)]
    csrf: String,
    consumer_scope_key: String,
    resource_generation: i64,
    #[serde(default)]
    expected_resource_version: String,
}

async fn binding_for_mutation(
    deps: &ConsoleDeps,
    org_slug: &str,
    binding_id: &str,
) -> Result<(OrgRecord, crate::db::StorageBindingRecord), Response> {
    let Some(org) = deps.db.org_by_slug(org_slug).await.map_err(internal)? else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    let Some(binding) = deps
        .db
        .storage_binding_by_stable_id(binding_id)
        .await
        .map_err(internal)?
    else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    if binding.org_id != Some(org.id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    Ok((org, binding))
}

async fn plan_binding_credential(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: Instant,
    org_slug: String,
    binding_id: String,
    form: BindingCredentialPlanForm,
    action: StorageCredentialAction,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(response) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingManage).await
    {
        return *response;
    }
    let (org, binding) = match binding_for_mutation(&deps, &org_slug, &binding_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, Scope::parse(&org.stable_id)) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let operation = match action {
        StorageCredentialAction::Set => "set",
        StorageCredentialAction::Rotate => "rotate",
    };
    let title = match action {
        StorageCredentialAction::Set => "Set storage credential",
        StorageCredentialAction::Rotate => "Rotate storage credential",
    };
    match deps
        .topology
        .plan_storage_binding_credential(
            &bearer,
            aos_proto_types::PlanStorageBindingCredentialRequest {
                storage_binding_id: binding.stable_id.clone(),
                purpose: form.purpose,
                secret_version_ref: form.secret_version_ref,
                credential_fingerprint: form.credential_fingerprint,
                expected_resource_version: form.expected_resource_version,
                idempotency_key: format!(
                    "console-binding-plan-{operation}-credential-{}",
                    uuid::Uuid::new_v4()
                ),
                expected_current_generation: form.expected_current_generation,
            },
            action,
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            title,
            &format!("/-/org/{org_slug}/storage-bindings/{binding_id}/credentials/{operation}"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

async fn apply_binding_credential(
    deps: ConsoleDeps,
    headers: HeaderMap,
    org_slug: String,
    binding_id: String,
    form: PlacementApplyForm,
    action: StorageCredentialAction,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(response) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingManage).await
    {
        return *response;
    }
    let (org, _) = match binding_for_mutation(&deps, &org_slug, &binding_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, Scope::parse(&org.stable_id)) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_storage_binding_credential(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            action,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/-/org/{org_slug}/storage-bindings/{binding_id}/credentials"
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

macro_rules! binding_credential_handlers {
    ($plan:ident, $apply:ident, $action:expr) => {
        pub(crate) async fn $plan(
            deps: ConsoleDeps,
            headers: HeaderMap,
            RequestStart(started): RequestStart,
            Path((org_slug, binding_id)): Path<(String, String)>,
            Form(form): Form<BindingCredentialPlanForm>,
        ) -> Response {
            plan_binding_credential(deps, headers, started, org_slug, binding_id, form, $action)
                .await
        }

        pub(crate) async fn $apply(
            deps: ConsoleDeps,
            headers: HeaderMap,
            Path((org_slug, binding_id)): Path<(String, String)>,
            Form(form): Form<PlacementApplyForm>,
        ) -> Response {
            apply_binding_credential(deps, headers, org_slug, binding_id, form, $action).await
        }
    };
}

binding_credential_handlers!(
    org_plan_set_binding_credential,
    org_set_binding_credential,
    StorageCredentialAction::Set
);
binding_credential_handlers!(
    org_plan_rotate_binding_credential,
    org_rotate_binding_credential,
    StorageCredentialAction::Rotate
);

async fn plan_binding_grant(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: Instant,
    org_slug: String,
    binding_id: String,
    form: BindingGrantPlanForm,
    action: ConsumerGrantAction,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(response) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingGrant).await
    {
        return *response;
    }
    let (org, binding) = match binding_for_mutation(&deps, &org_slug, &binding_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, Scope::parse(&org.stable_id)) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let operation = match action {
        ConsumerGrantAction::Grant => "grant",
        ConsumerGrantAction::Revoke => "revoke",
    };
    match deps
        .topology
        .plan_storage_binding_grant(
            &bearer,
            aos_proto_types::PlanConsumerScopeGrantRequest {
                resource_kind: "storage_binding".to_string(),
                resource_stable_id: binding.stable_id.clone(),
                resource_generation: form.resource_generation,
                consumer_scope_key: form.consumer_scope_key,
                expected_resource_version: form.expected_resource_version,
                idempotency_key: format!(
                    "console-binding-plan-{operation}-{}",
                    uuid::Uuid::new_v4()
                ),
                pin_resolutions: Vec::new(),
            },
            action,
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            if action == ConsumerGrantAction::Grant {
                "Grant storage-binding access"
            } else {
                "Revoke storage-binding access"
            },
            &format!("/-/org/{org_slug}/storage-bindings/{binding_id}/consumer-grants/{operation}"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

async fn apply_binding_grant(
    deps: ConsoleDeps,
    headers: HeaderMap,
    org_slug: String,
    binding_id: String,
    form: PlacementApplyForm,
    action: ConsumerGrantAction,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(response) =
        require_org_perm(&deps, &session, &scope, Permission::StorageBindingGrant).await
    {
        return *response;
    }
    let (org, _) = match binding_for_mutation(&deps, &org_slug, &binding_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let bearer = match session.topology_bearer(&deps, Scope::parse(&org.stable_id)) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_storage_binding_grant(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            action,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/-/org/{org_slug}/storage-bindings/{binding_id}/consumer-grants"
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

macro_rules! binding_grant_handlers {
    ($plan:ident, $apply:ident, $action:expr) => {
        pub(crate) async fn $plan(
            deps: ConsoleDeps,
            headers: HeaderMap,
            RequestStart(started): RequestStart,
            Path((org_slug, binding_id)): Path<(String, String)>,
            Form(form): Form<BindingGrantPlanForm>,
        ) -> Response {
            plan_binding_grant(deps, headers, started, org_slug, binding_id, form, $action).await
        }

        pub(crate) async fn $apply(
            deps: ConsoleDeps,
            headers: HeaderMap,
            Path((org_slug, binding_id)): Path<(String, String)>,
            Form(form): Form<PlacementApplyForm>,
        ) -> Response {
            apply_binding_grant(deps, headers, org_slug, binding_id, form, $action).await
        }
    };
}

binding_grant_handlers!(
    org_plan_grant_binding_scope,
    org_grant_binding_scope,
    ConsumerGrantAction::Grant
);
binding_grant_handlers!(
    org_plan_revoke_binding_scope,
    org_revoke_binding_scope,
    ConsumerGrantAction::Revoke
);

/// `POST /-/org/{org}/delete` form: the typed-confirmation slug.
#[derive(serde::Deserialize)]
pub(crate) struct OrgDeleteForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    confirm: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// `POST /-/org/{org}/delete` — plan or apply organization offboarding.
pub(crate) async fn org_delete(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    Form(form): Form<OrgDeleteForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if let Some(deny) = require_org_perm(&deps, &session, &scope, Permission::IamAdmin).await {
        return *deny;
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !form.plan_id.is_empty() {
        return match deps
            .topology
            .apply_delete_organization(
                &bearer,
                form.plan_id.clone(),
                form.confirmation_hash,
                console_apply_idempotency_key(&form.plan_id),
            )
            .await
        {
            Ok(true) => Redirect::to("/-/orgs").into_response(),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    if form.confirm.trim() != org_slug {
        return (
            StatusCode::BAD_REQUEST,
            "type the organization slug to confirm",
        )
            .into_response();
    }
    let Some(org) = deps.db.org_by_slug(&org_slug).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match deps
        .topology
        .plan_delete_organization(
            &bearer,
            aos_proto_types::PlanDeleteOrganizationRequest {
                slug: org_slug.clone(),
                expected_resource_version: org.resource_version.to_string(),
                idempotency_key: format!("console-plan-delete-org-{}", uuid::Uuid::new_v4()),
            },
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Delete organization",
            &format!("/-/org/{org_slug}/danger/delete"),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

/// Gate a mutation on `perm` at an org `scope`: `403` for a member who lacks it,
/// `404` for a non-member, `None` when allowed.
async fn require_org_perm(
    deps: &ConsoleDeps,
    session: &Session,
    scope: &Scope,
    perm: Permission,
) -> Option<Box<Response>> {
    if session.allows(&deps.db, perm, scope).await {
        return None;
    }
    if session.allows(&deps.db, Permission::Read, scope).await {
        Some(Box::new(
            (StatusCode::FORBIDDEN, "insufficient permission").into_response(),
        ))
    } else {
        Some(Box::new(StatusCode::NOT_FOUND.into_response()))
    }
}

// -- instance settings ------------------------------------------------------

/// `GET /-/instance` — the instance-settings page (instance admins only).
pub(crate) async fn instance_settings(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_instance_settings(&deps, &session, None, started).await
}

/// Render the instance-settings page; instance-admin only.
async fn render_instance_settings(
    deps: &ConsoleDeps,
    session: &Session,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    render_instance(deps, session, "overview", notice, started).await
}

/// Renders an instance-settings section for an instance administrator.
///
/// The `storage` section loads the storage inventory; `overview`, `branding`,
/// `identity`, and `resource-defaults` load the editable
/// [`InstanceSettings`](crate::db::InstanceSettings) bundle.
async fn render_instance(
    deps: &ConsoleDeps,
    session: &Session,
    active: &str,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    if !session
        .allows(&deps.db, Permission::IamAdmin, &Scope::root())
        .await
    {
        return (StatusCode::FORBIDDEN, "instance admin required").into_response();
    }
    if active == "storage" {
        let binding = match deps.db.instance_default_binding().await {
            Ok(b) => b,
            Err(err) => return internal(err),
        };
        return Html(console::instance_storage_page(
            &session.email,
            deps.default_storage_location.as_deref(),
            binding.as_ref(),
            notice,
            started,
        ))
        .into_response();
    }
    let settings = match deps.db.instance_settings().await {
        Ok(s) => s,
        Err(err) => return internal(err),
    };
    let csrf = session.csrf();
    let html = match active {
        "branding" => {
            console::instance_branding_page(&session.email, &csrf, &settings, notice, started)
        }
        "resource-defaults" => console::instance_resource_defaults_page(
            &session.email,
            &csrf,
            &settings,
            notice,
            started,
        ),
        "identity" => {
            console::instance_settings_page(&session.email, &csrf, &settings, notice, started)
        }
        _ => console::instance_overview_page(&session.email, notice, started),
    };
    Html(html).into_response()
}

/// Resolve the instance-admin session for an instance-settings mutation,
/// CSRF-checked. Returns the session, or the response to short-circuit with.
async fn require_instance_admin(
    deps: &ConsoleDeps,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<Session, Response> {
    let session = match require_session(deps, headers).await {
        Ok(s) => s,
        Err(resp) => return Err(*resp),
    };
    if let Err(resp) = check_csrf(&session, csrf) {
        return Err(*resp);
    }
    if !session
        .allows(&deps.db, Permission::IamAdmin, &Scope::root())
        .await
    {
        return Err((StatusCode::FORBIDDEN, "instance admin required").into_response());
    }
    Ok(session)
}

/// `GET /-/instance/storage-bindings` — the instance storage inventory.
pub(crate) async fn instance_storage(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_instance(&deps, &session, "storage", None, started).await
}

/// `GET /-/instance/branding` — the branding tab (instance admins only).
pub(crate) async fn instance_branding(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_instance(&deps, &session, "branding", None, started).await
}

/// `GET /-/instance/identity-and-signup` — authentication and signup policy.
pub(crate) async fn instance_identity(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    render_instance(&deps, &session, "identity", None, started).await
}

/// `GET /-/instance/resource-defaults` — defaults for newly created resources.
pub(crate) async fn instance_resource_defaults(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_instance(&deps, &session, "resource-defaults", None, started).await
}

/// `POST /-/instance/identity-and-signup` form.
#[derive(serde::Deserialize)]
pub(crate) struct InstanceSettingsForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    signup_policy: String,
    #[serde(default)]
    signup_domains: String,
    #[serde(default)]
    password_login: Option<String>,
    #[serde(default)]
    session_lifetime_secs: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// Plans a browser-originated instance-settings mutation through the same
/// retained-control service used by Connect clients.
async fn plan_instance_settings_web(
    deps: &ConsoleDeps,
    session: &Session,
    title: &str,
    apply_action: &str,
    values: std::collections::HashMap<String, String>,
    started: Instant,
) -> Response {
    let bearer = match session.topology_bearer(deps, Scope::root()) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let current = match deps.topology.instance_settings(&bearer).await {
        Ok(current) => current,
        Err(error) => return (StatusCode::CONFLICT, error.to_string()).into_response(),
    };
    let request_idempotency_key = format!("console-plan-instance-{}", uuid::Uuid::new_v4());
    match deps
        .topology
        .plan_instance_settings(
            &bearer,
            aos_proto_types::PlanSetInstanceSettingsRequest {
                values,
                clear: Vec::new(),
                expected_resource_version: current.resource_version,
                idempotency_key: request_idempotency_key,
            },
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            title,
            apply_action,
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

/// Applies an instance-settings plan and refreshes process-local presentation
/// state only after the authoritative apply has committed.
async fn apply_instance_settings_web(
    deps: &ConsoleDeps,
    session: &Session,
    plan_id: String,
    confirmation_hash: String,
) -> Result<(), Response> {
    let bearer = session
        .topology_bearer(deps, Scope::root())
        .map_err(internal)?;
    let idempotency_key = console_apply_idempotency_key(&plan_id);
    let response = deps
        .topology
        .apply_instance_settings(&bearer, plan_id, confirmation_hash, idempotency_key)
        .await
        .map_err(|error| (StatusCode::CONFLICT, error.to_string()).into_response())?;
    let settings = response.settings.ok_or_else(|| {
        internal(anyhow::anyhow!(
            "instance-settings apply response omitted settings"
        ))
    })?;
    crate::web::console_render::set_caches_public(settings.caches_public);
    crate::web::console_render::set_site_chrome(
        (!settings.site_title.is_empty()).then_some(settings.site_title.as_str()),
        (!settings.tagline.is_empty()).then_some(settings.tagline.as_str()),
        (!settings.announcement.is_empty()).then_some(settings.announcement.as_str()),
        (!settings.tos_url.is_empty()).then_some(settings.tos_url.as_str()),
        (!settings.privacy_url.is_empty()).then_some(settings.privacy_url.as_str()),
        (!settings.support_url.is_empty()).then_some(settings.support_url.as_str()),
    );
    Ok(())
}

/// Updates signup and identity policy for instance administrators.
pub(crate) async fn instance_settings_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<InstanceSettingsForm>,
) -> Response {
    let session = match require_instance_admin(&deps, &headers, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !form.plan_id.is_empty() {
        if let Err(response) =
            apply_instance_settings_web(&deps, &session, form.plan_id, form.confirmation_hash).await
        {
            return response;
        }
        return render_instance(
            &deps,
            &session,
            "identity",
            Some("Signup &amp; identity saved."),
            started,
        )
        .await;
    }
    let domains = form
        .signup_domains
        .split(|character: char| character == ',' || character.is_whitespace())
        .filter(|domain| !domain.is_empty())
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(",");
    let values = std::collections::HashMap::from([
        ("signup_policy".to_string(), form.signup_policy),
        ("signup_domains".to_string(), domains),
        (
            "password_login".to_string(),
            if form.password_login.is_some() {
                "on".to_string()
            } else {
                "off".to_string()
            },
        ),
        (
            "session_lifetime_secs".to_string(),
            form.session_lifetime_secs,
        ),
    ]);
    plan_instance_settings_web(
        &deps,
        &session,
        "Review signup & identity settings",
        "/-/instance/identity-and-signup",
        values,
        started,
    )
    .await
}

/// `POST /-/instance/resource-defaults` form.
#[derive(serde::Deserialize)]
pub(crate) struct InstanceResourceDefaultsForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    caches_public: Option<String>,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// Updates defaults applied to newly created instance resources.
pub(crate) async fn instance_resource_defaults_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<InstanceResourceDefaultsForm>,
) -> Response {
    let session = match require_instance_admin(&deps, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if !form.plan_id.is_empty() {
        if let Err(response) =
            apply_instance_settings_web(&deps, &session, form.plan_id, form.confirmation_hash).await
        {
            return response;
        }
        return render_instance(
            &deps,
            &session,
            "resource-defaults",
            Some("Resource defaults saved."),
            started,
        )
        .await;
    }
    let caches_public = form.caches_public.is_some();
    plan_instance_settings_web(
        &deps,
        &session,
        "Review instance resource defaults",
        "/-/instance/resource-defaults",
        std::collections::HashMap::from([(
            "caches_public".to_string(),
            if caches_public { "on" } else { "off" }.to_string(),
        )]),
        started,
    )
    .await
}

/// `POST /-/instance/branding` form: site title, tagline, banner, footer links.
#[derive(serde::Deserialize)]
pub(crate) struct InstanceBrandingForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    site_title: String,
    #[serde(default)]
    tagline: String,
    #[serde(default)]
    announcement: String,
    #[serde(default)]
    tos_url: String,
    #[serde(default)]
    privacy_url: String,
    #[serde(default)]
    support_url: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// `POST /-/instance/branding` — update branding + footer (instance admins).
pub(crate) async fn instance_branding_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<InstanceBrandingForm>,
) -> Response {
    let session = match require_instance_admin(&deps, &headers, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !form.plan_id.is_empty() {
        if let Err(response) =
            apply_instance_settings_web(&deps, &session, form.plan_id, form.confirmation_hash).await
        {
            return response;
        }
        return render_instance(
            &deps,
            &session,
            "branding",
            Some("Branding saved."),
            started,
        )
        .await;
    }
    // Footer links render as `href`s; require an http(s) scheme so a blank or
    // `javascript:`/`data:` value can never become a stored XSS vector.
    for (label, value) in [
        ("ToS URL", &form.tos_url),
        ("Privacy URL", &form.privacy_url),
        ("Support URL", &form.support_url),
    ] {
        let v = value.trim();
        if !v.is_empty() && crate::url_guard::require_http_scheme(v).is_err() {
            return (
                StatusCode::BAD_REQUEST,
                format!("{label} must be an http(s):// URL"),
            )
                .into_response();
        }
    }
    let values = std::collections::HashMap::from([
        ("site_title".to_string(), form.site_title),
        ("tagline".to_string(), form.tagline),
        ("announcement".to_string(), form.announcement),
        ("tos_url".to_string(), form.tos_url),
        ("privacy_url".to_string(), form.privacy_url),
        ("support_url".to_string(), form.support_url),
    ]);
    plan_instance_settings_web(
        &deps,
        &session,
        "Review instance branding",
        "/-/instance/branding",
        values,
        started,
    )
    .await
}

/// The effective absolute session lifetime in seconds for newly created sessions.
///
/// The instance `session_lifetime_secs` setting overrides the built-in
/// [`ABSOLUTE_LIFETIME_SECS`] when an operator has set a positive value;
/// otherwise the built-in default applies. Read at login so a change takes
/// effect for subsequent logins without a restart; a malformed or non-positive
/// stored value falls back to the default (fail safe). The same value is used
/// for both the session row's expiry and the cookie `Max-Age`, so they cannot
/// drift.
async fn effective_session_lifetime(deps: &ConsoleDeps) -> i64 {
    match deps.db.instance_config_get("session_lifetime_secs").await {
        Ok(Some(v)) => v
            .parse::<i64>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(ABSOLUTE_LIFETIME_SECS),
        _ => ABSOLUTE_LIFETIME_SECS,
    }
}

/// Whether local password login is offered on this instance.
///
/// Reads the instance `password_login` setting, which defaults to enabled; only
/// the explicit off spellings (`off`/`false`/`0`) disable it. A database error
/// fails open to enabled, so a transient read failure never locks every
/// password user out.
async fn password_login_enabled(deps: &ConsoleDeps) -> bool {
    match deps.db.instance_config_get("password_login").await {
        Ok(Some(v)) => !matches!(v.as_str(), "off" | "false" | "0"),
        _ => true,
    }
}

// -- registry resolution for console pages ----------------------------------

/// Resolve a registry by its flat slug, or by longest-prefix over the full
/// request path for a nested-canonical slug.
async fn resolve_registry(
    deps: &ConsoleDeps,
    slug: &str,
    uri: &axum::http::Uri,
) -> anyhow::Result<Option<RegistryRecord>> {
    if let Some(reg) = deps.db.registry_by_slug(slug).await? {
        return Ok(Some(reg));
    }
    let path = uri.path().trim_start_matches('/');
    let head = path.split("/-/").next().unwrap_or(path);
    resolve_by_prefix(deps, head.trim_end_matches('/')).await
}

/// Resolve a registry whose canonical slug is the longest registered prefix of
/// `path`, returning the record when `path` is exactly a registry slug.
///
/// The flat console routes capture only a single path segment, so a nested
/// registry (`acme/infra/prod/cdn`) is reconstructed here by walking the path
/// from the longest prefix down to the first segment and returning the first
/// registered match. Only an exact (no-tail) match is accepted by the callers.
async fn resolve_by_prefix(
    deps: &ConsoleDeps,
    path: &str,
) -> anyhow::Result<Option<RegistryRecord>> {
    let path = path.trim_matches('/');
    if path.is_empty() {
        return Ok(None);
    }
    let segments: Vec<&str> = path.split('/').collect();
    for end in (1..=segments.len()).rev() {
        let candidate = segments[..end].join("/");
        if let Some(reg) = deps.db.registry_by_slug(&candidate).await? {
            // Only an exact match (the whole path is the slug) is a console
            // target; a prefix match with a trailing tail is not.
            if end == segments.len() {
                return Ok(Some(reg));
            }
            return Ok(None);
        }
    }
    Ok(None)
}

// -- registry settings / management landing ---------------------------------

/// `GET /{slug}/-/settings` — the registry management landing page.
pub(crate) async fn registry_settings(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    registry_settings_view(&deps, &session, &registry, None, "overview", started).await
}

/// Renders one exact registry management section.
async fn registry_settings_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<&str>,
    active: &str,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, &registry).await;
    let Some(page) = RegistryPage::parse(active) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let required = REGISTRY_PAGES
        .iter()
        .find(|spec| spec.key == page)
        .map_or(Permission::Read, |spec| spec.permission);
    if let Some(deny) = require_org_perm(deps, session, &scope, required).await {
        return *deny;
    }
    let result_outcome = async {
        let navigation = navigation_permissions(&deps.db, session, &scope).await?;
        let can_delete = session.allows(&deps.db, Permission::IamAdmin, &scope).await;
        let placements =
            placement_overview_rows(deps, crate::db::SurfaceTarget::Registry(registry.id)).await?;
        let (policies, equivalences) =
            placement_policy_overview_rows(deps, crate::db::SurfaceTarget::Registry(registry.id))
                .await?;
        Ok::<_, anyhow::Error>(console::registry_settings_page(
            &session.email,
            registry,
            &session.csrf(),
            &placements,
            &policies,
            &equivalences,
            can_delete,
            result,
            active,
            &navigation,
            started,
        ))
    }
    .await;
    match result_outcome {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

/// `GET /{slug}/-/settings/access` — registry identity and access policy.
pub(crate) async fn registry_access(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "access").await
}

/// `GET /{slug}/-/settings/placements` — registry storage and replicas.
pub(crate) async fn registry_placements(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "placements").await
}

/// Shows immutable placement-policy revisions for a registry.
pub(crate) async fn registry_placement_policies(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "placement-policies").await
}

/// Shows confirmed placement equivalences for a registry.
pub(crate) async fn registry_placement_equivalences(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "placement-equivalences").await
}

/// Renders a registry placement creation form backed by owner bindings.
pub(crate) async fn registry_new_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let Some(org_id) = registry.org_id else {
        return (
            StatusCode::CONFLICT,
            "registry has no organization bindings",
        )
            .into_response();
    };
    match deps.db.list_storage_binding_read_summaries(org_id).await {
        Ok(bindings) => Html(console::new_placement_page(
            &session.email,
            "Add registry placement",
            &format!("/{}/-/settings/placements/plan-create", registry.slug),
            &session.csrf(),
            &bindings,
            started,
        ))
        .into_response(),
        Err(error) => internal(error),
    }
}

/// Plans creation of one registry placement.
pub(crate) async fn registry_plan_create_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<PlacementCreateForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let spec = match form.spec() {
        Ok(spec) => spec,
        Err(response) => return response,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_create_placement(
            &bearer,
            TopologySurface::Registry(registry.slug.clone()),
            spec,
            format!("console-registry-plan-create-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Create registry placement",
            &format!("/{}/-/settings/placements/create", registry.slug),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies a reviewed registry placement creation.
pub(crate) async fn registry_create_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    registry_apply_basic_placement_plan(
        deps,
        headers,
        uri,
        slug,
        form,
        PlacementPlanOperation::Create,
    )
    .await
}

/// Plans promotion of one registry placement without changing authority.
pub(crate) async fn registry_plan_promote_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path((slug, placement)): Path<(String, String)>,
    Form(form): Form<PlacementPlanForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_promote_placement(
            &bearer,
            TopologySurface::Registry(registry.slug.clone()),
            placement.clone(),
            form.expected_resource_version,
            format!("console-registry-promote-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            &format!("Promote placement · {placement}"),
            &format!(
                "/{}/-/settings/placements/{placement}/promote",
                registry.slug
            ),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies one previously reviewed registry-placement promotion plan.
pub(crate) async fn registry_promote_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, _placement)): Path<(String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .promote_placement(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(_) => Redirect::to(&format!("/{}/-/settings/placements", registry.slug)).into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Plans replacement of a registry placement's mutable desired fields.
pub(crate) async fn registry_plan_update_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path((slug, placement)): Path<(String, String)>,
    Form(form): Form<PlacementUpdateForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_update_placement(
            &bearer,
            TopologySurface::Registry(registry.slug.clone()),
            placement.clone(),
            form.expected_resource_version,
            PlacementUpdateSpec {
                desired_state: form.desired_state,
                desired_read_enabled: form.desired_read_enabled.is_some(),
                read_order: form.read_order,
            },
            format!("console-registry-plan-update-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            &format!("Update registry placement · {placement}"),
            &format!(
                "/{}/-/settings/placements/{}/update",
                registry.slug,
                urlencode(&placement),
            ),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies a reviewed registry placement update.
pub(crate) async fn registry_update_placement(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, _placement)): Path<(String, String)>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    registry_apply_basic_placement_plan(
        deps,
        headers,
        uri,
        slug,
        form,
        PlacementPlanOperation::Update,
    )
    .await
}

/// Plans cancellation of a registry's in-flight placement promotion.
pub(crate) async fn registry_plan_cancel_placement_promotion(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<TopologyPlanForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_cancel_placement_promotion(
            &bearer,
            TopologySurface::Registry(registry.slug.clone()),
            format!("console-registry-plan-cancel-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Cancel registry placement promotion",
            &format!("/{}/-/settings/placements/cancel-promotion", registry.slug),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies a reviewed registry promotion cancellation.
pub(crate) async fn registry_cancel_placement_promotion(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    registry_apply_basic_placement_plan(
        deps,
        headers,
        uri,
        slug,
        form,
        PlacementPlanOperation::CancelPromotion,
    )
    .await
}

async fn registry_apply_basic_placement_plan(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    slug: String,
    form: PlacementApplyForm,
    operation: PlacementPlanOperation,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_placement_plan(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            operation,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(()) => {
            Redirect::to(&format!("/{}/-/settings/placements", registry.slug)).into_response()
        }
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

async fn registry_plan_placement_lifecycle(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: Instant,
    uri: axum::http::Uri,
    slug: String,
    placement: String,
    form: PlacementPlanForm,
    action: PlacementLifecycleAction,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let operation = match action {
        PlacementLifecycleAction::Drain => "drain",
        PlacementLifecycleAction::Delete => "delete",
    };
    match deps
        .topology
        .plan_placement_lifecycle(
            &bearer,
            TopologySurface::Registry(registry.slug.clone()),
            placement.clone(),
            form.expected_resource_version,
            action,
            format!("console-registry-plan-{operation}-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            &format!(
                "{} registry placement · {placement}",
                operation_title(operation)
            ),
            &format!(
                "/{}/-/settings/placements/{}/{operation}",
                registry.slug,
                urlencode(&placement),
            ),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

async fn registry_apply_placement_lifecycle(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    slug: String,
    form: PlacementApplyForm,
    action: PlacementLifecycleAction,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .apply_placement_lifecycle(
            &bearer,
            form.plan_id.clone(),
            form.confirmation_hash,
            action,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(()) => {
            Redirect::to(&format!("/{}/-/settings/placements", registry.slug)).into_response()
        }
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

macro_rules! registry_placement_lifecycle_handlers {
    ($plan:ident, $apply:ident, $action:expr) => {
        pub(crate) async fn $plan(
            deps: ConsoleDeps,
            headers: HeaderMap,
            RequestStart(started): RequestStart,
            uri: axum::http::Uri,
            Path((slug, placement)): Path<(String, String)>,
            Form(form): Form<PlacementPlanForm>,
        ) -> Response {
            registry_plan_placement_lifecycle(
                deps, headers, started, uri, slug, placement, form, $action,
            )
            .await
        }

        pub(crate) async fn $apply(
            deps: ConsoleDeps,
            headers: HeaderMap,
            uri: axum::http::Uri,
            Path((slug, _placement)): Path<(String, String)>,
            Form(form): Form<PlacementApplyForm>,
        ) -> Response {
            registry_apply_placement_lifecycle(deps, headers, uri, slug, form, $action).await
        }
    };
}

registry_placement_lifecycle_handlers!(
    registry_plan_drain_placement,
    registry_drain_placement,
    PlacementLifecycleAction::Drain
);
registry_placement_lifecycle_handlers!(
    registry_plan_delete_placement,
    registry_delete_placement,
    PlacementLifecycleAction::Delete
);

/// Plans transition of a registry to an explicitly read-only topology.
pub(crate) async fn registry_plan_remove_write_authority(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<TopologyPlanForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .plan_remove_write_authority(&bearer, TopologySurface::Registry(registry.slug.clone()))
        .await
    {
        Ok(plan) => Html(console::topology_plan_page(
            &session.email,
            "Remove registry write authority",
            &format!(
                "/{}/-/settings/placements/remove-write-authority",
                registry.slug
            ),
            &session.csrf(),
            &plan,
            started,
        ))
        .into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Applies a reviewed transition of a registry to read-only topology.
pub(crate) async fn registry_remove_write_authority(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<PlacementApplyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match deps
        .topology
        .remove_write_authority(
            &bearer,
            TopologySurface::Registry(registry.slug.clone()),
            form.plan_id.clone(),
            form.confirmation_hash,
            console_apply_idempotency_key(&form.plan_id),
        )
        .await
    {
        Ok(_) => Redirect::to(&format!("/{}/-/settings/placements", registry.slug)).into_response(),
        Err(error) => internal(anyhow::anyhow!(error.to_string())),
    }
}

/// Shows the registry's ordered signed consumer cache stack.
pub(crate) async fn registry_cache_stack(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "cache-stack").await
}

/// Shows cache-owned retention subscriptions pointing at the registry.
pub(crate) async fn registry_retention_consumers(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "retention-consumers").await
}

/// Shows cache-owned population targets pointing at the registry.
pub(crate) async fn registry_population_targets(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "population-targets").await
}

/// `GET /{slug}/-/settings/channels` — the registry's signed rollout channels.
pub(crate) async fn registry_channels(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session.allows(&deps.db, Permission::Read, &scope).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    match deps.db.list_channels(registry.id).await {
        Ok(channels) => Html(console::registry_channels_page(
            &session.email,
            &registry,
            &channels,
            &navigation,
            started,
        ))
        .into_response(),
        Err(error) => internal(error),
    }
}

/// `GET /{slug}/-/settings/operations` — registry operation history.
pub(crate) async fn registry_operations(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "operations").await
}

/// `GET /{slug}/-/settings/danger` — the registry's danger-zone tab.
pub(crate) async fn registry_danger(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "danger").await
}

/// Shared body for the registry settings section tabs: resolve the registry,
/// then render the requested `active` section through [`registry_settings_view`].
async fn registry_settings_section(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    active: &str,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    registry_settings_view(&deps, &session, &registry, None, active, started).await
}

// -- registry-scoped access tokens -----------------------------------------

/// `GET /{slug}/-/settings/tokens` — the caller's tokens at the registry.
pub(crate) async fn tokens(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Query(page): Query<PageQuery>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokens_view(&deps, &session, &registry, &headers, page.page(), started).await
}

/// Render the tokens page (read path): visibility-gated, no result banner.
async fn tokens_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    _headers: &HeaderMap,
    page_number: usize,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::TokensSelf, &scope)
        .await
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    render_tokens(deps, session, registry, None, page_number, started).await
}

/// The token-create action: CSRF + TokensSelf gate, mint, show secret once.
async fn tokens_create_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    want_read: bool,
    want_publish: bool,
    plan_id: String,
    confirmation_hash: String,
    started: Instant,
    headers: &HeaderMap,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(session, headers) {
        return *resp;
    }
    let scope = registry_scope(&deps.db, &registry).await;
    if !session.allows(&deps.db, Permission::IamAdmin, &scope).await {
        return (StatusCode::FORBIDDEN, "iam.admin required").into_response();
    }
    let scope_key = scope.as_str().to_string();
    let bearer = match session.topology_bearer(deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !plan_id.is_empty() {
        let idempotency_key = console_apply_idempotency_key(&plan_id);
        return match deps
            .topology
            .apply_access_token_issue(&bearer, plan_id, confirmation_hash, idempotency_key)
            .await
        {
            Ok(response) => {
                render_tokens(
                    deps,
                    session,
                    registry,
                    Some(("New token created", &response.secret)),
                    1,
                    started,
                )
                .await
            }
            Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
        };
    }
    let mut permissions = Vec::new();
    if want_read {
        permissions.push("read".to_string());
    }
    if want_publish {
        permissions.push("publish".to_string());
    }
    let plan = match deps
        .topology
        .plan_access_token_issue(
            &bearer,
            aos_proto_types::PlanIssueAccessTokenRequest {
                owner: format!("user:{}", session.email),
                scope: scope_key,
                permissions,
                ttl_secs: 0,
                expected_resource_version: String::new(),
                idempotency_key: format!("console-plan-access-token-{}", uuid::Uuid::new_v4()),
                comment: format!("Web console token for {}", registry.slug),
            },
        )
        .await
    {
        Ok(plan) => plan,
        Err(error) => return (StatusCode::CONFLICT, error.to_string()).into_response(),
    };
    Html(console::topology_plan_page(
        &session.email,
        "Review access token issuance",
        &format!("/{}/-/settings/tokens", registry.slug),
        &session.csrf(),
        &plan,
        started,
    ))
    .into_response()
}

/// Plans or applies retirement of one exact token generation.
async fn tokens_modify_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    token_id: &str,
    plan_id: String,
    confirmation_hash: String,
    started: Instant,
    headers: &HeaderMap,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = ensure_owns_token(deps, session, token_id).await {
        return *resp;
    }
    if let Err(response) = require_sudo(session, headers) {
        return *response;
    }
    let scope = registry_scope(&deps.db, &registry).await;
    if !session.allows(&deps.db, Permission::IamAdmin, &scope).await {
        return (StatusCode::FORBIDDEN, "iam.admin required").into_response();
    }
    let bearer = match session.topology_bearer(deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !plan_id.is_empty() {
        let idempotency_key = console_apply_idempotency_key(&plan_id);
        return match deps
            .topology
            .apply_access_token_retirement(&bearer, plan_id, confirmation_hash, idempotency_key)
            .await
        {
            Ok(()) => {
                deps.invalidate_token_cache(token_id).await;
                Redirect::to(&format!("/{}/-/settings/tokens", registry.slug)).into_response()
            }
            Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
        };
    }
    let plan = match deps
        .topology
        .plan_access_token_retirement(
            &bearer,
            token_id.to_string(),
            "active".to_string(),
            format!("console-plan-retire-token-{}", uuid::Uuid::new_v4()),
        )
        .await
    {
        Ok(plan) => plan,
        Err(error) => return (StatusCode::CONFLICT, error.to_string()).into_response(),
    };
    Html(console::topology_plan_page(
        &session.email,
        "Review access token retirement",
        &format!("/{}/-/settings/tokens/{token_id}/revoke", registry.slug),
        &session.csrf(),
        &plan,
        started,
    ))
    .into_response()
}

/// Render the tokens page, optionally with a one-time secret result.
async fn render_tokens(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<(&str, &str)>,
    page_number: usize,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, registry).await;
    let can_create = session.allows(&deps.db, Permission::IamAdmin, &scope).await;
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let all = match deps.db.list_tokens_for(session.principal()).await {
        Ok(tokens) => tokens,
        Err(err) => return internal(err),
    };
    let mine: Vec<_> = all
        .into_iter()
        .filter(|(_, s, _)| Scope::parse(s) == scope)
        .collect();
    Html(console::tokens_page(
        &session.email,
        registry,
        &session.csrf(),
        &mine,
        can_create,
        result,
        page_number,
        &navigation,
        started,
    ))
    .into_response()
}

/// `POST /{slug}/-/settings/tokens` form: which permissions to grant.
#[derive(serde::Deserialize)]
pub(crate) struct TokenCreateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    perm_read: Option<String>,
    #[serde(default)]
    perm_publish: Option<String>,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// `POST /{slug}/-/settings/tokens` — mint a token at the registry scope.
pub(crate) async fn tokens_create(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<TokenCreateForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokens_create_action(
        &deps,
        &session,
        &registry,
        &form.csrf,
        form.perm_read.is_some(),
        form.perm_publish.is_some(),
        form.plan_id,
        form.confirmation_hash,
        started,
        &headers,
    )
    .await
}

/// `POST` token-retirement form: the target token id and optional reviewed plan.
#[derive(serde::Deserialize)]
pub(crate) struct TokenIdForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// Revokes one of the caller's tokens through its resource URL.
pub(crate) async fn tokens_revoke(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path((slug, token_id)): Path<(String, String)>,
    Form(form): Form<TokenIdForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokens_modify_action(
        &deps,
        &session,
        &registry,
        &form.csrf,
        &token_id,
        form.plan_id,
        form.confirmation_hash,
        started,
        &headers,
    )
    .await
}

/// Verify the session user owns the token being retired, else 403.
async fn ensure_owns_token(
    deps: &ConsoleDeps,
    session: &Session,
    token_id: &str,
) -> Result<(), Box<Response>> {
    let owned = deps
        .db
        .list_tokens_for(session.principal())
        .await
        .map(|tokens| tokens.iter().any(|(id, _, _)| id == token_id))
        .unwrap_or(false);
    if owned {
        Ok(())
    } else {
        Err(Box::new(
            (StatusCode::FORBIDDEN, "not your token").into_response(),
        ))
    }
}

// -- channel rollout console ------------------------------------------------

/// Renders the canonical registry-settings channel rollout page.
pub(crate) async fn channel_console(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path((slug, name)): Path<(String, String)>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if !session.allows(&deps.db, Permission::Read, &scope).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    render_channel_console(&deps, &session, &registry, &name, &navigation, started).await
}

/// Render the channel console.
async fn render_channel_console(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    name: &str,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> Response {
    let result = async {
        let channels = deps.db.list_channels(registry.id).await?;
        let Some(channel) = channels.into_iter().find(|c| c.name == name) else {
            return Ok(None);
        };
        Ok::<_, anyhow::Error>(Some(console::channel_console(
            &session.email,
            registry,
            &channel,
            navigation_permissions,
            started,
        )))
    }
    .await;
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

// -- retained signing keys --------------------------------------------------

/// Renders the canonical organization signing-key inventory.
pub(crate) async fn org_keys(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_keys(&deps, &session, &org_slug, None, started).await
}

/// Renders the org signing-key page through the shared public service.
async fn render_org_keys(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    let scope = organization_scope(&deps.db, org_slug).await;
    if !session
        .allows(&deps.db, Permission::KeysManage, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "keys.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(org_slug).await? else {
            return Ok(None);
        };
        let bearer = session.topology_bearer(deps, Scope::parse(&org.stable_id))?;
        let keys = deps
            .topology
            .signing_keys(&bearer, org.stable_id.clone())
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok::<_, anyhow::Error>(Some(console::org_signing_keys_page(
            &session.email,
            &org,
            &session.csrf(),
            &keys,
            notice,
            &navigation,
            started,
        )))
    }
    .await;
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Form for planning or applying external signing-key enrollment.
#[derive(serde::Deserialize)]
pub(crate) struct OrgKeysForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    operation: String,
    #[serde(default)]
    key_id: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    public_key_fingerprint: String,
    #[serde(default)]
    expected_resource_version: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// Plans or applies external signing-key enrollment.
pub(crate) async fn org_keys_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    Form(form): Form<OrgKeysForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if !session
        .allows(&deps.db, Permission::KeysManage, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "keys.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope.clone()) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let operation = if form.operation.is_empty() {
        "enroll"
    } else {
        form.operation.as_str()
    };
    if !form.plan_id.is_empty() {
        let result = match operation {
            "enroll" => {
                deps.topology
                    .apply_signing_key_enrollment(
                        &bearer,
                        form.plan_id.clone(),
                        form.confirmation_hash,
                        console_apply_idempotency_key(&form.plan_id),
                    )
                    .await
            }
            "rotate" => {
                deps.topology
                    .apply_signing_key_rotation(
                        &bearer,
                        form.plan_id.clone(),
                        form.confirmation_hash,
                        console_apply_idempotency_key(&form.plan_id),
                    )
                    .await
            }
            "retire" => {
                deps.topology
                    .apply_signing_key_retirement(
                        &bearer,
                        form.plan_id.clone(),
                        form.confirmation_hash,
                        console_apply_idempotency_key(&form.plan_id),
                    )
                    .await
            }
            _ => return (StatusCode::BAD_REQUEST, "unknown signing-key operation").into_response(),
        };
        return match result {
            Ok(_) => {
                let notice = match operation {
                    "rotate" => "Signing key rotated.",
                    "retire" => "Signing key retired.",
                    _ => "Signing key enrolled.",
                };
                render_org_keys(&deps, &session, &org_slug, Some(notice), started).await
            }
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    let (title, plan) = match operation {
        "enroll" | "rotate" => {
            let request = aos_proto_types::PlanSigningKeyMutationRequest {
                scope_key: scope.as_str().to_string(),
                name: form.key_id,
                public_key: form.public_key,
                public_key_fingerprint: form.public_key_fingerprint,
                custody: "external".to_string(),
                expected_resource_version: form.expected_resource_version,
                idempotency_key: format!(
                    "console-plan-{operation}-signing-key-{}",
                    uuid::Uuid::new_v4()
                ),
            };
            let plan = if operation == "rotate" {
                deps.topology
                    .plan_signing_key_rotation(&bearer, request)
                    .await
            } else {
                deps.topology
                    .plan_signing_key_enrollment(&bearer, request)
                    .await
            };
            (
                if operation == "rotate" {
                    "Rotate signing key"
                } else {
                    "Enroll signing key"
                },
                plan,
            )
        }
        "retire" => (
            "Retire signing key",
            deps.topology
                .plan_signing_key_retirement(
                    &bearer,
                    aos_proto_types::PlanRetireSigningKeyRequest {
                        scope_key: scope.as_str().to_string(),
                        name: form.key_id,
                        expected_resource_version: form.expected_resource_version,
                        idempotency_key: format!(
                            "console-plan-retire-signing-key-{}",
                            uuid::Uuid::new_v4()
                        ),
                    },
                )
                .await,
        ),
        _ => return (StatusCode::BAD_REQUEST, "unknown signing-key operation").into_response(),
    };
    match plan {
        Ok(plan) => Html(console::signing_topology_plan_page(
            &session.email,
            title,
            &format!("/-/org/{org_slug}/signing-keys"),
            &session.csrf(),
            &plan,
            operation,
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

// -- webhooks ---------------------------------------------------------------

/// `GET /-/org/{org}/webhooks` — the org webhook management page.
pub(crate) async fn org_webhooks(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_webhooks(&deps, &session, &org_slug, started).await
}

/// Render the org webhooks page.
async fn render_org_webhooks(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    started: Instant,
) -> Response {
    let scope = organization_scope(&deps.db, org_slug).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(org_slug).await? else {
            return Ok(None);
        };
        let webhooks = deps.db.list_webhooks(org.id).await?;
        Ok::<_, anyhow::Error>(Some(console::org_webhooks_page(
            &session.email,
            &org,
            &session.csrf(),
            &webhooks,
            &navigation,
            started,
        )))
    }
    .await;
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

// -- single sign-on (OIDC IdP + email domains) ------------------------------

/// `GET /-/org/{org}/sso` — the org SSO (OIDC IdP + domains) page.
pub(crate) async fn org_sso(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_sso(&deps, &session, &org_slug, None, started).await
}

/// Render the org SSO page.
async fn render_org_sso(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    let scope = organization_scope(&deps.db, org_slug).await;
    if !session.allows(&deps.db, Permission::IamAdmin, &scope).await {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "iam.admin required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let bearer = match session.topology_bearer(deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(org_slug).await? else {
            return Ok(None);
        };
        let idp = match deps
            .topology
            .identity_provider(&bearer, org_slug.to_string())
            .await
        {
            Ok(response) => response.identity_provider,
            Err(crate::service::RpcError::NotFound(_)) => None,
            Err(error) => return Err(anyhow::anyhow!(error.to_string())),
        };
        let domains = deps
            .topology
            .organization_domains(&bearer, org_slug.to_string())
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok::<_, anyhow::Error>(Some(console::org_sso_page(
            &session.email,
            &org,
            &session.csrf(),
            idp.as_ref(),
            &domains,
            notice,
            &navigation,
            started,
        )))
    }
    .await;
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/sso` — review or apply an IdP/domain mutation.
pub(crate) async fn org_sso_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let fields = parse_form(&String::from_utf8_lossy(&body));
    let field = |key: &str| fields.get(key).map(String::as_str).unwrap_or("");
    if let Err(response) = check_csrf(&session, field("csrf")) {
        return *response;
    }
    if let Err(response) = require_sudo(&session, &headers) {
        return *response;
    }
    let scope = organization_scope(&deps.db, &org_slug).await;
    if !session.allows(&deps.db, Permission::IamAdmin, &scope).await {
        return (StatusCode::FORBIDDEN, "iam.admin required").into_response();
    }
    let bearer = match session.topology_bearer(&deps, scope) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let operation = field("op");
    let plan_id = field("plan_id");
    if !plan_id.is_empty() {
        let confirmation_hash = field("confirmation_hash").to_string();
        let idempotency_key = console_apply_idempotency_key(plan_id);
        let result = match operation {
            "apply-set-idp" => deps
                .topology
                .apply_identity_provider(
                    &bearer,
                    plan_id.to_string(),
                    confirmation_hash,
                    idempotency_key,
                )
                .await
                .map(|_| "Identity provider saved.".to_string()),
            "apply-remove-idp" => deps
                .topology
                .apply_identity_provider_removal(
                    &bearer,
                    plan_id.to_string(),
                    confirmation_hash,
                    idempotency_key,
                )
                .await
                .map(|_| "Identity provider removed.".to_string()),
            "apply-add-domain" => deps
                .topology
                .apply_organization_domain_claim(
                    &bearer,
                    plan_id.to_string(),
                    confirmation_hash,
                    idempotency_key,
                )
                .await
                .map(|response| match response.domain {
                    Some(domain) => format!(
                        "Claimed {}. Publish this TXT record: {}",
                        domain.domain, domain.txt_challenge
                    ),
                    None => "Domain claimed.".to_string(),
                }),
            "apply-verify-domain" => deps
                .topology
                .apply_organization_domain_verification(
                    &bearer,
                    plan_id.to_string(),
                    confirmation_hash,
                    idempotency_key,
                )
                .await
                .map(|response| match response.domain {
                    Some(domain) => format!("Verified {}.", domain.domain),
                    None => "Domain verified.".to_string(),
                }),
            "apply-remove-domain" => deps
                .topology
                .apply_organization_domain_release(
                    &bearer,
                    plan_id.to_string(),
                    confirmation_hash,
                    idempotency_key,
                )
                .await
                .map(|_| "Domain released.".to_string()),
            _ => return (StatusCode::BAD_REQUEST, "unknown reviewed operation").into_response(),
        };
        return match result {
            Ok(notice) => render_org_sso(&deps, &session, &org_slug, Some(&notice), started).await,
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }

    let current_idp = match deps
        .topology
        .identity_provider(&bearer, org_slug.clone())
        .await
    {
        Ok(response) => response.identity_provider,
        Err(crate::service::RpcError::NotFound(_)) => None,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let domains = match deps
        .topology
        .organization_domains(&bearer, org_slug.clone())
        .await
    {
        Ok(domains) => domains,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let idempotency_key = format!("console-sso-plan-{}", uuid::Uuid::new_v4());
    let planned = match operation {
        "set-idp" => {
            let client_secret = field("client_secret").to_string();
            let clear_client_secret = field("clear_client_secret") == "1";
            if clear_client_secret && !client_secret.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    "enter a replacement client secret or select clear, not both",
                )
                    .into_response();
            }
            deps.topology
                .plan_identity_provider(
                    &bearer,
                    aos_proto_types::PlanSetIdentityProviderRequest {
                        org_slug: org_slug.clone(),
                        issuer: field("issuer").trim().to_string(),
                        authorization_endpoint: field("auth_url").trim().to_string(),
                        token_endpoint: field("token_url").trim().to_string(),
                        jwks_uri: field("jwks_uri").trim().to_string(),
                        client_id: field("client_id").trim().to_string(),
                        replace_client_secret: clear_client_secret || !client_secret.is_empty(),
                        client_secret,
                        scopes: field("scopes").trim().to_string(),
                        groups_claim: field("groups_claim").trim().to_string(),
                        role_map_json: field("role_map").trim().to_string(),
                        allow_jit: field("allow_jit") == "1",
                        enforce_sso: field("enforce_sso") == "1",
                        default_role: field("default_role").trim().to_string(),
                        expected_resource_version: current_idp.as_ref().map_or_else(
                            || "absent".to_string(),
                            |idp| idp.resource_version.clone(),
                        ),
                        idempotency_key,
                    },
                )
                .await
                .map(|plan| ("Save identity provider", "apply-set-idp", plan))
        }
        "remove-idp" => {
            let Some(idp) = current_idp else {
                return StatusCode::NOT_FOUND.into_response();
            };
            deps.topology
                .plan_identity_provider_removal(
                    &bearer,
                    aos_proto_types::PlanRemoveIdentityProviderRequest {
                        org_slug: org_slug.clone(),
                        expected_resource_version: idp.resource_version,
                        idempotency_key,
                    },
                )
                .await
                .map(|plan| ("Remove identity provider", "apply-remove-idp", plan))
        }
        "add-domain" => deps
            .topology
            .plan_organization_domain_claim(
                &bearer,
                aos_proto_types::PlanClaimOrganizationDomainRequest {
                    org_slug: org_slug.clone(),
                    domain: field("domain").trim().to_string(),
                    expected_resource_version: "absent".to_string(),
                    idempotency_key,
                },
            )
            .await
            .map(|plan| ("Claim email domain", "apply-add-domain", plan)),
        "rotate-domain" => {
            let requested = field("domain").trim();
            let Some(domain) = domains.iter().find(|domain| domain.domain == requested) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            deps.topology
                .plan_organization_domain_claim(
                    &bearer,
                    aos_proto_types::PlanClaimOrganizationDomainRequest {
                        org_slug: org_slug.clone(),
                        domain: domain.domain.clone(),
                        expected_resource_version: domain.resource_version.clone(),
                        idempotency_key,
                    },
                )
                .await
                .map(|plan| ("Rotate domain challenge", "apply-add-domain", plan))
        }
        "verify-domain" | "remove-domain" => {
            let requested = field("domain").trim();
            let Some(domain) = domains.iter().find(|domain| domain.domain == requested) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if operation == "verify-domain" {
                deps.topology
                    .plan_organization_domain_verification(
                        &bearer,
                        aos_proto_types::PlanVerifyOrganizationDomainRequest {
                            org_slug: org_slug.clone(),
                            domain: domain.domain.clone(),
                            expected_resource_version: domain.resource_version.clone(),
                            idempotency_key,
                        },
                    )
                    .await
                    .map(|plan| ("Verify email domain", "apply-verify-domain", plan))
            } else {
                deps.topology
                    .plan_organization_domain_release(
                        &bearer,
                        aos_proto_types::PlanReleaseOrganizationDomainRequest {
                            org_slug: org_slug.clone(),
                            domain: domain.domain.clone(),
                            expected_resource_version: domain.resource_version.clone(),
                            idempotency_key,
                        },
                    )
                    .await
                    .map(|plan| ("Release email domain", "apply-remove-domain", plan))
            }
        }
        _ => return (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    };
    match planned {
        Ok((title, apply_operation, plan)) => Html(console::reviewed_operation_plan_page(
            &session.email,
            title,
            &format!("/-/org/{org_slug}/sso"),
            &session.csrf(),
            &plan,
            apply_operation,
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
// -- registry delivery and upstream mirroring -------------------------------

/// Shows simultaneous client delivery routes.
pub(crate) async fn registry_delivery(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if let Some(deny) = require_org_perm(&deps, &session, &scope, Permission::RouteRead).await {
        return *deny;
    }
    let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    match delivery_route_overview_rows(&deps, crate::db::SurfaceTarget::Registry(registry.id)).await
    {
        Ok(routes) => Html(console::registry_delivery_page(
            &session.email,
            &registry,
            &routes,
            &navigation,
            started,
        ))
        .into_response(),
        Err(error) => internal(error),
    }
}

/// Shows exact canonical audience selections separately from route inventory.
pub(crate) async fn registry_canonical_audiences(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if let Some(deny) = require_org_perm(&deps, &session, &scope, Permission::RouteRead).await {
        return *deny;
    }
    let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    match delivery_route_overview_rows(&deps, crate::db::SurfaceTarget::Registry(registry.id)).await
    {
        Ok(routes) => Html(console::registry_canonical_audiences_page(
            &session.email,
            &registry,
            &routes,
            &navigation,
            started,
        ))
        .into_response(),
        Err(error) => internal(error),
    }
}

/// `GET /{slug}/-/settings/upstream-mirror` — upstream synchronization state.
pub(crate) async fn registry_upstream_mirror(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    match deps.db.mirror_source(registry.id).await {
        Ok(mirror) => Html(console::registry_upstream_mirror_page(
            &session.email,
            &registry,
            mirror.as_ref(),
            &navigation,
            started,
        ))
        .into_response(),
        Err(error) => internal(error),
    }
}

// -- keys -------------------------------------------------------------------

/// `GET /{slug}/-/keys` — the key roster management page.
pub(crate) async fn keys(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Query(page): Query<PageQuery>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    keys_view(&deps, &session, &registry, &headers, page.page(), started).await
}

/// Render the key roster page: visibility-gated.
async fn keys_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    _headers: &HeaderMap,
    page_number: usize,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, registry).await;
    if !session
        .allows(&deps.db, Permission::KeysManage, &scope)
        .await
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let roster = match deps.db.list_roster(registry.id).await {
        Ok(roster) => roster,
        Err(err) => return internal(err),
    };
    let can_manage = session
        .allows(&deps.db, Permission::KeysManage, &scope)
        .await;
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let bearer = match session.topology_bearer(deps, Scope::parse(&registry.owner_scope_key)) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    let signing_keys = match deps
        .topology
        .signing_keys(&bearer, registry.owner_scope_key.clone())
        .await
    {
        Ok(keys) => keys,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let signing_usage = match deps
        .db
        .signing_key_usage(&registry.stable_id, "registry_publication")
        .await
    {
        Ok(usage) => usage,
        Err(error) => return internal(error),
    };
    let mut channel_usages = Vec::new();
    let channels = match deps.db.list_channels(registry.id).await {
        Ok(channels) => channels,
        Err(error) => return internal(error),
    };
    for channel in channels {
        let consumer_stable_id = format!("channel:{}:{}", registry.stable_id, channel.name);
        let usage = match deps
            .db
            .signing_key_usage(&consumer_stable_id, "channel_frontier")
            .await
        {
            Ok(usage) => usage,
            Err(error) => return internal(error),
        };
        channel_usages.push(console::ChannelSigningUsageRow {
            name: channel.name,
            usage,
        });
    }
    Html(console::keys_page(
        &session.email,
        registry,
        &session.csrf(),
        &roster,
        signing_usage.as_ref(),
        &signing_keys,
        &channel_usages,
        can_manage,
        page_number,
        &navigation,
        started,
    ))
    .into_response()
}

/// Reviewed retained publication-key usage from registry settings.
#[derive(serde::Deserialize)]
pub(crate) struct RegistrySigningKeyForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    channel_name: String,
    #[serde(default)]
    key_generation: String,
    #[serde(default)]
    signing_key_stable_id: String,
    #[serde(default)]
    signing_key_generation: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    expected_resource_version: String,
    #[serde(default)]
    plan_id: String,
    #[serde(default)]
    confirmation_hash: String,
}

/// Plans or applies the registry's exact publication signing-key usage.
pub(crate) async fn keys_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<RegistrySigningKeyForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = check_csrf(&session, &form.csrf) {
        return *response;
    }
    if let Err(response) = require_sudo(&session, &headers) {
        return *response;
    }
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(registry) => registry,
        Err(error) => return internal(error),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope = registry_scope(&deps.db, &registry).await;
    if let Some(response) = require_org_perm(&deps, &session, &scope, Permission::KeysManage).await
    {
        return *response;
    }
    let bearer = match session.topology_bearer(&deps, Scope::parse(&registry.owner_scope_key)) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    if !form.plan_id.is_empty() {
        return match deps
            .topology
            .apply_signing_key_usage(
                &bearer,
                form.plan_id.clone(),
                form.confirmation_hash,
                console_apply_idempotency_key(&form.plan_id),
            )
            .await
        {
            Ok(_) => keys_view(&deps, &session, &registry, &headers, 1, started).await,
            Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    }
    let (key_id, generation) = if form.state == "active" {
        match form.key_generation.rsplit_once(':') {
            Some((key_id, generation)) => (key_id.to_string(), generation.to_string()),
            None => {
                return (StatusCode::BAD_REQUEST, "select a signing-key generation").into_response()
            }
        }
    } else if form.state == "detached" {
        (form.signing_key_stable_id, form.signing_key_generation)
    } else {
        return (StatusCode::BAD_REQUEST, "invalid signing usage state").into_response();
    };
    let generation = match generation.parse::<u64>() {
        Ok(generation) if generation > 0 => generation,
        _ => return (StatusCode::BAD_REQUEST, "invalid signing-key generation").into_response(),
    };
    let (consumer_stable_id, purpose, title) = match form.purpose.as_str() {
        "" | "registry_publication" => (
            registry.stable_id.clone(),
            "registry_publication".to_string(),
            "Change registry publication key",
        ),
        "channel_frontier" => {
            let channels = match deps.db.list_channels(registry.id).await {
                Ok(channels) => channels,
                Err(error) => return internal(error),
            };
            if form.channel_name.is_empty()
                || !channels
                    .iter()
                    .any(|channel| channel.name == form.channel_name)
            {
                return (StatusCode::BAD_REQUEST, "unknown registry channel").into_response();
            }
            (
                format!("channel:{}:{}", registry.stable_id, form.channel_name),
                "channel_frontier".to_string(),
                "Change channel frontier key",
            )
        }
        _ => return (StatusCode::BAD_REQUEST, "invalid signing usage purpose").into_response(),
    };
    match deps
        .topology
        .plan_signing_key_usage(
            &bearer,
            aos_proto_types::PlanSigningKeyUsageRequest {
                consumer_stable_id,
                purpose,
                signing_key_stable_id: key_id,
                signing_key_generation: generation,
                state: form.state,
                expected_resource_version: form.expected_resource_version,
                idempotency_key: format!(
                    "console-plan-registry-signing-usage-{}",
                    uuid::Uuid::new_v4()
                ),
            },
        )
        .await
    {
        Ok(plan) => Html(console::signing_topology_plan_page(
            &session.email,
            title,
            &format!("/{}/-/settings/signing-keys", registry.slug),
            &session.csrf(),
            &plan,
            "usage",
            started,
        ))
        .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

/// Renders the signing-key rotation wizard.
pub(crate) async fn keys_rotate(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    keys_rotate_view(&deps, &session, &registry, &headers, started).await
}

/// Render the rotation wizard: visibility-gated.
async fn keys_rotate_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    _headers: &HeaderMap,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, registry).await;
    if !session
        .allows(&deps.db, Permission::KeysManage, &scope)
        .await
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    Html(console::keys_rotate_page(
        &session.email,
        registry,
        &navigation,
        started,
    ))
    .into_response()
}

// -- publishes --------------------------------------------------------------

/// `GET /{slug}/-/publishes` — the publish-pipeline status view.
pub(crate) async fn publishes(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    publishes_view(&deps, &session, &registry, started).await
}

/// Render the publish-pipeline view: visibility-gated.
async fn publishes_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, registry).await;
    if !session.allows(&deps.db, Permission::Read, &scope).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let result = async {
        let status = deps.db.index_status(registry.id).await?;
        let releases = deps.db.list_releases(registry.id).await?;
        let audit: Vec<_> = deps
            .db
            .list_audit(&registry.scope_key)
            .await?
            .into_iter()
            .filter(|a| {
                a.action.contains("publish")
                    || a.action.contains("index")
                    || a.action.contains("channel")
            })
            .take(20)
            .collect();
        Ok::<_, anyhow::Error>(console::publishes_page(
            &session.email,
            registry,
            status.as_ref(),
            &releases,
            &audit,
            &navigation,
            started,
        ))
    }
    .await;
    match result {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

// -- git-backed config change requests --------------------------------------

/// `GET /{slug}/-/settings/configuration` — the git-backed configuration page.
///
/// Renders the current committed `registry.toml` in a textarea for a
/// `registry.configure`-bearing admin to edit and submit as a change request.
pub(crate) async fn config_edit(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    config_edit_view(&deps, &session, &registry, None, started).await
}

/// Render the config-edit page, optionally with a just-created change-request
/// `result` (its change id and merge command).
async fn config_edit_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<(&str, &str)>,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, registry).await;
    let can_edit = session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await;
    if !can_edit {
        return StatusCode::NOT_FOUND.into_response();
    }
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };
    let current = match current_registry_toml(deps, registry).await {
        Ok(toml) => toml,
        Err(err) => return internal(err),
    };
    // Auto-generate the structured form from the parsed config for editors.
    // A file the form can't represent (malformed, or carrying fields outside
    // the schema) and the read-only view both fall back to the raw-TOML page,
    // which shows the committed file verbatim so nothing is hidden or dropped.
    match crate::web::config_form::parse_model(&current) {
        Some(model) if can_edit => Html(console::registry_config_form_page(
            &session.email,
            registry,
            &session.csrf(),
            &model,
            can_edit,
            result,
            &navigation,
            started,
        ))
        .into_response(),
        _ => Html(console::config_edit_page(
            &session.email,
            registry,
            &session.csrf(),
            &current,
            can_edit,
            result,
            &navigation,
            started,
        ))
        .into_response(),
    }
}

/// Load a registry's current committed `registry.toml`, or an empty string
/// when the registry has not been indexed yet (no HEAD to read from).
///
/// Reads the base commit's tree through the
/// [`SurfaceProvider`](crate::fetch::SurfaceProvider) read port
/// ([`surface`](ConsoleDeps::surface)).
///
/// # Errors
///
/// Returns an error when resolving the read surface fails, when the indexed
/// HEAD oid is malformed, or when reading the committed file fails.
async fn current_registry_toml(
    deps: &ConsoleDeps,
    registry: &RegistryRecord,
) -> anyhow::Result<String> {
    let Some(head_hex) = deps
        .db
        .index_status(registry.id)
        .await?
        .and_then(|s| s.last_indexed_commit)
    else {
        return Ok(String::new());
    };
    let head = aos_registry_surface::object::Oid::from_hex(&head_hex)?;
    let fetch = crate::placement_read::TopologySurfaceFetch::for_verified_git_objects(
        Arc::clone(&deps.db),
        Arc::clone(&deps.surface),
        crate::db::SurfaceTarget::Registry(registry.id),
    );
    Ok(
        crate::git::load_committed_file(&fetch, head, "registry.toml")
            .await?
            .unwrap_or_default(),
    )
}

/// `POST /{slug}/-/settings/configuration` — submits a configuration change request.
///
/// The body is the auto-generated config form (not raw TOML): it is decoded
/// ([`crate::web::config_form::parse_submission`]), CSRF-checked, and
/// `registry.configure`-gated, then merged back into the committed
/// `registry.toml` ([`crate::web::config_form::build_toml`]) and proposed as a
/// draft change request to `refs/hub/changes/<id>` via
/// [`crate::gitwrite::propose_config_change`]. A validation error re-renders
/// the form with the message and the user's preserved input; a successful
/// proposal re-renders with the new change id and `apr change merge` command.
pub(crate) async fn config_submit(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    body: String,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let sub = crate::web::config_form::parse_submission(&body);
    if let Err(resp) = check_csrf(&session, &sub.csrf) {
        return *resp;
    }
    let scope = registry_scope(&deps.db, &registry).await;
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }

    let existing = match current_registry_toml(&deps, &registry).await {
        Ok(toml) => toml,
        Err(err) => return internal(err),
    };
    match crate::web::config_form::build_toml(&existing, &sub) {
        Ok(contents) => {
            let trimmed = |s: &str| {
                let t = s.trim();
                (!t.is_empty()).then(|| t.to_string())
            };
            let meta = crate::gitwrite::ProposeMeta {
                title: trimmed(&sub.title),
                body: trimmed(&sub.body),
            };
            propose_registry_config(&deps, &session, &registry, &contents, meta, started).await
        }
        Err(err) => {
            // Re-render the form with the error and the user's preserved input;
            // recover whether an advanced [caches] stack exists from the file.
            let mut model =
                crate::web::config_form::model_from_submission(&sub, format!("{err:#}"));
            model.has_cache_stack = crate::web::config_form::parse_model(&existing)
                .map(|m| m.has_cache_stack)
                .unwrap_or(false);
            let scope = registry_scope(&deps.db, &registry).await;
            let navigation = match navigation_permissions(&deps.db, &session, &scope).await {
                Ok(permissions) => permissions,
                Err(error) => return internal(error),
            };
            Html(console::registry_config_form_page(
                &session.email,
                &registry,
                &session.csrf(),
                &model,
                true,
                None,
                &navigation,
                started,
            ))
            .into_response()
        }
    }
}

/// Propose a rebuilt `registry.toml` as a git-backed change request, then
/// re-render the config page with the new change id and merge command.
///
/// CSRF and `registry.configure` are assumed already checked by the caller.
/// Reads the base commit through the
/// [`SurfaceProvider`](crate::fetch::SurfaceProvider) read port and writes the
/// draft through the
/// [`SurfaceWriteProvider`](crate::surface_write::SurfaceWriteProvider) write
/// port; a proposal error renders as a `400`.
async fn propose_registry_config(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    contents: &str,
    meta: crate::gitwrite::ProposeMeta,
    started: Instant,
) -> Response {
    let fetch = crate::placement_read::TopologySurfaceFetch::for_verified_git_objects(
        Arc::clone(&deps.db),
        Arc::clone(&deps.surface),
        crate::db::SurfaceTarget::Registry(registry.id),
    );
    let placement = match deps
        .db
        .reconciled_surface_writer(crate::db::SurfaceTarget::Registry(registry.id))
        .await
    {
        Ok(placement) => placement,
        Err(err) => return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    };
    let writer = match deps.surface_write.placement_writer(&placement).await {
        Ok(writer) => writer,
        Err(err) => return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    };
    let proposed = crate::gitwrite::propose_config_change(
        &deps.db,
        deps.sealer.as_ref(),
        &fetch,
        writer.as_ref(),
        registry,
        "registry.toml",
        contents,
        "user",
        Some(session.auth.user_id),
        &session.email,
        crate::clock::now_unix_secs(),
        meta,
    )
    .await;
    match proposed {
        Ok(proposed) => {
            let merge_url = format!(
                "{}/{}",
                deps.external_url.trim_end_matches('/'),
                registry.slug
            );
            let merge_command = crate::git::merge_command(&merge_url, &proposed.change_id);
            config_edit_view(
                deps,
                session,
                registry,
                Some((proposed.change_id.as_str(), &merge_command)),
                started,
            )
            .await
        }
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

/// `GET /{slug}/-/settings/change-requests` — the git-backed change list.
///
/// The shared registry read gate runs first, preserving a private registry's
/// `404` nondisclosure contract. A principal who may read the registry but
/// lacks `audit.read` receives `403`.
pub(crate) async fn changes(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(response) = authorize_registry_read(&deps, &registry, &headers).await {
        return *response;
    }
    let filter = console::ChangesFilter::parse(query_value(&uri, "state").as_deref());
    changes_view(&deps, &session, &registry, filter, started).await
}

/// Render the change-request list page for a resolved registry.
///
/// Gated to `audit.read` after the caller has enforced registry readability.
/// Renders the Open/Closed/All tabbed list; each row links to the change's
/// detail page.
async fn changes_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    filter: console::ChangesFilter,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, registry).await;
    if !session
        .allows(&deps.db, Permission::AuditRead, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "audit.read required").into_response();
    }
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };

    let result = async {
        let changesets = deps.db.list_changesets(&registry.scope_key).await?;
        let mut rows: Vec<console::ChangeListRow> = Vec::new();
        for cs in changesets.into_iter().filter(|cs| cs.git_ref.is_some()) {
            let comment_count = deps
                .db
                .list_change_comments(&cs.change_id)
                .await
                .map(|c| c.len())
                .unwrap_or(0);
            let title = cs
                .title
                .clone()
                .or_else(|| cs.summary.clone())
                .unwrap_or_default();
            rows.push(console::ChangeListRow {
                change_id: cs.change_id,
                title,
                status: cs.status,
                closed: cs.closed_at.is_some(),
                actor_label: cs.actor_label,
                created_at: cs.created_at,
                comment_count,
            });
        }
        Ok::<_, anyhow::Error>(console::changes_page(
            &session.email,
            registry,
            &rows,
            filter,
            &navigation,
            started,
        ))
    }
    .await;
    match result {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

/// Reads a single query-string value by key from a request URI.
fn query_value(uri: &axum::http::Uri, key: &str) -> Option<String> {
    uri.query().and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    })
}

/// Renders one canonical settings change-request detail page.
///
/// Renders the PR-style Conversation / Diff / Checks views for one git-backed
/// change request. Registry readability is checked before `audit.read`, so a
/// hidden private registry returns `404` while a readable principal without
/// audit permission receives `403`. A change outside the resolved registry (or
/// one that is not git-backed) also returns `404`.
pub(crate) async fn change_detail(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path((slug, id)): Path<(String, String)>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&deps, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(response) = authorize_registry_read(&deps, &registry, &headers).await {
        return *response;
    }
    change_detail_view(&deps, &session, &registry, &id, &uri, started).await
}

/// Renders the change-request detail page for a resolved registry and change id.
async fn change_detail_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    change_id: &str,
    uri: &axum::http::Uri,
    started: Instant,
) -> Response {
    let scope = registry_scope(&deps.db, registry).await;
    if !session
        .allows(&deps.db, Permission::AuditRead, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "audit.read required").into_response();
    }
    let can_close = session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await;
    let navigation = match navigation_permissions(&deps.db, session, &scope).await {
        Ok(permissions) => permissions,
        Err(error) => return internal(error),
    };

    let result = async {
        let Some(cs) = deps.db.changeset(change_id).await? else {
            return Ok(None);
        };
        // Scope guard: only this registry's own git-backed change requests.
        if cs.git_ref.is_none() || Scope::try_parse(&cs.scope).as_ref() != Some(&scope) {
            return Ok(None);
        }

        let revisions = deps.db.list_revisions(change_id).await.unwrap_or_default();
        let file_revs: Vec<_> = revisions
            .into_iter()
            .filter(|r| r.object_type == "registry_file")
            .collect();
        let file_diffs = file_revs
            .iter()
            .map(|r| {
                (
                    r.object_id.clone(),
                    crate::git::unified_diff(
                        &r.object_id,
                        r.old_json.as_deref().unwrap_or_default(),
                        r.new_json.as_deref().unwrap_or_default(),
                    ),
                )
            })
            .collect();
        let checks = compute_config_checks(
            file_revs
                .first()
                .and_then(|r| r.new_json.as_deref())
                .unwrap_or_default(),
        );

        let comments = deps
            .db
            .list_change_comments(change_id)
            .await
            .unwrap_or_default();
        let reviews = deps
            .db
            .list_change_reviews(change_id)
            .await
            .unwrap_or_default();
        let timeline = build_change_timeline(&cs, &comments, &reviews);

        let merge_url = format!(
            "{}/{}",
            deps.external_url.trim_end_matches('/'),
            registry.slug
        );
        let merge_command =
            crate::git::merge_command(&merge_url, &config::ChangeId(cs.change_id.clone()));

        let detail = console::ChangeDetailView {
            title: cs
                .title
                .clone()
                .or_else(|| cs.summary.clone())
                .unwrap_or_default(),
            body: cs.body.clone().unwrap_or_default(),
            status: cs.status.clone(),
            closed: cs.closed_at.is_some(),
            actor_label: cs.actor_label.clone(),
            created_at: cs.created_at,
            git_commit: cs.git_commit.clone().unwrap_or_default(),
            base_branch: "HEAD".to_string(),
            file_diffs,
            checks,
            timeline,
            merge_command,
            view: console::DetailTab::parse(query_value(uri, "view").as_deref()),
            can_review: true,
            can_close,
            csrf: session.csrf(),
            change_id: cs.change_id,
        };
        Ok(Some(console::change_detail_page(
            &session.email,
            registry,
            &detail,
            &navigation,
            started,
        )))
    }
    .await;

    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Recomputes the change-request validation checks from the proposed
/// `registry.toml` text, fully tolerant of malformed input (never panics).
fn compute_config_checks(new_text: &str) -> Vec<console::CheckRow> {
    use aos_registry_surface::manifest::RegistryRootConfig;

    let mut checks = Vec::new();
    let schema = toml::from_str::<RegistryRootConfig>(new_text);
    checks.push(console::CheckRow {
        ok: schema.is_ok(),
        label: "schema valid".to_string(),
        note: schema
            .as_ref()
            .err()
            .map(|e| e.to_string().lines().next().unwrap_or_default().to_string())
            .unwrap_or_default(),
    });

    match toml::from_str::<toml::Value>(new_text) {
        Ok(val) => {
            let name_ok = val
                .get("registry")
                .and_then(|r| r.get("name"))
                .and_then(toml::Value::as_str)
                .is_some_and(|n| !n.trim().is_empty());
            checks.push(console::CheckRow {
                ok: name_ok,
                label: "registry name set".to_string(),
                note: String::new(),
            });

            let caches = val.get("caches").and_then(toml::Value::as_array);
            let count = caches.map_or(0, Vec::len);
            let prio_ok = caches.is_none_or(|arr| {
                arr.iter().all(|e| {
                    e.get("priority")
                        .is_none_or(|p| p.as_integer().is_some_and(|i| i >= 0))
                })
            });
            let url_ok = caches.is_none_or(|arr| {
                arr.iter().all(|e| {
                    e.get("url")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|u| !u.trim().is_empty())
                })
            });
            checks.push(console::CheckRow {
                ok: prio_ok,
                label: "cache priorities parse".to_string(),
                note: format!("{count} cache(s)"),
            });
            checks.push(console::CheckRow {
                ok: url_ok,
                label: "cache URLs present".to_string(),
                note: String::new(),
            });
        }
        Err(_) => {
            checks.push(console::CheckRow {
                ok: false,
                label: "registry name set".to_string(),
                note: "file does not parse".to_string(),
            });
        }
    }
    checks
}

/// Synthesizes the conversation timeline from the change-set lifecycle stamps,
/// its comments, and its reviews, sorted oldest-first.
fn build_change_timeline(
    cs: &crate::db::ChangesetRow,
    comments: &[crate::db::ChangeCommentRow],
    reviews: &[crate::db::ChangeReviewRow],
) -> Vec<console::TimelineItem> {
    use console::{TimelineItem, TimelineKind};

    let mut items = vec![TimelineItem {
        kind: TimelineKind::Opened,
        actor: cs.actor_label.clone(),
        when: cs.created_at,
        body: String::new(),
    }];
    for c in comments {
        items.push(TimelineItem {
            kind: TimelineKind::Comment,
            actor: c.actor_label.clone(),
            when: c.created_at,
            body: c.body.clone(),
        });
    }
    for r in reviews {
        let kind = if r.verdict == "approve" {
            TimelineKind::Approved
        } else {
            TimelineKind::RequestedChanges
        };
        items.push(TimelineItem {
            kind,
            actor: r.actor_label.clone(),
            when: r.created_at,
            body: r.body.clone().unwrap_or_default(),
        });
    }
    if let Some(when) = cs.closed_at {
        items.push(TimelineItem {
            kind: TimelineKind::Closed,
            actor: String::new(),
            when,
            body: String::new(),
        });
    }
    if cs.status == "applied" {
        items.push(TimelineItem {
            kind: TimelineKind::Merged,
            actor: String::new(),
            when: cs.applied_at.unwrap_or(cs.created_at),
            body: String::new(),
        });
    }
    if cs.status == "reverted" {
        items.push(TimelineItem {
            kind: TimelineKind::Reverted,
            actor: String::new(),
            when: cs.applied_at.unwrap_or(cs.created_at),
            body: String::new(),
        });
    }
    items.sort_by_key(|i| i.when);
    items
}

/// CSRF-only form for the close/reopen actions.
///
/// All fields default so a missing CSRF token deserializes to `""` and is
/// rejected by [`check_csrf`] with a `403` (rather than a `422` from the `Form`
/// extractor), keeping CSRF the first gate — matching `config_submit`.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub(crate) struct ChangeActionForm {
    /// The session CSRF token.
    pub csrf: String,
}

/// A discussion-comment submission.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub(crate) struct ChangeCommentForm {
    /// The session CSRF token.
    pub csrf: String,
    /// The comment text.
    pub body: String,
}

/// An advisory-review submission.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub(crate) struct ChangeReviewForm {
    /// The session CSRF token.
    pub csrf: String,
    /// `approve` or `request_changes`.
    pub verdict: String,
    /// Optional review note.
    pub body: String,
}

/// Loads a change request for a mutating action.
///
/// The helper resolves the registry, enforces its read/nondisclosure contract,
/// validates CSRF, checks `perm`, and confirms the change is one of that
/// registry's git-backed requests. It returns the loaded change on success or
/// the response to return on denial.
async fn authorize_change_action(
    deps: &ConsoleDeps,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    slug: &str,
    change_id: &str,
    csrf: &str,
    perm: Permission,
) -> Result<(Session, RegistryRecord, crate::db::ChangesetRow), Response> {
    let session = require_session(deps, headers).await.map_err(|r| *r)?;
    let Some(registry) = resolve_registry(deps, slug, uri).await.map_err(internal)? else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    authorize_registry_read(deps, &registry, headers)
        .await
        .map_err(|response| *response)?;
    if let Err(resp) = check_csrf(&session, csrf) {
        return Err(*resp);
    }
    let scope = registry_scope(&deps.db, &registry).await;
    if !session.allows(&deps.db, perm, &scope).await {
        return Err((StatusCode::FORBIDDEN, "insufficient permission").into_response());
    }
    let Some(cs) = deps.db.changeset(change_id).await.map_err(internal)? else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    if cs.git_ref.is_none() || Scope::try_parse(&cs.scope).as_ref() != Some(&scope) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    Ok((session, registry, cs))
}

/// A 303 redirect back to a change's detail page (post/redirect/get).
fn redirect_to_change(slug: &str, change_id: &str) -> Response {
    Redirect::to(&format!("/{slug}/-/settings/change-requests/{change_id}")).into_response()
}

/// Posts a discussion comment to one change request.
///
/// Gated to `audit.read` (anyone who can see the change may discuss it).
pub(crate) async fn change_comment(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, id)): Path<(String, String)>,
    Form(form): Form<ChangeCommentForm>,
) -> Response {
    let (session, _registry, cs) = match authorize_change_action(
        &deps,
        &headers,
        &uri,
        &slug,
        &id,
        &form.csrf,
        Permission::AuditRead,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let body = form.body.trim();
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty comment").into_response();
    }
    if let Err(err) = deps
        .db
        .add_change_comment(
            &cs.change_id,
            "user",
            Some(session.auth.user_id),
            &session.email,
            body,
        )
        .await
    {
        return internal(err);
    }
    redirect_to_change(&slug, &cs.change_id)
}

/// Submits an advisory review to one change request.
///
/// Gated to `audit.read`. Reviews are advisory: there is no server-side merge,
/// so an approval gates nothing — it is recorded for the timeline.
pub(crate) async fn change_review(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, id)): Path<(String, String)>,
    Form(form): Form<ChangeReviewForm>,
) -> Response {
    let (session, _registry, cs) = match authorize_change_action(
        &deps,
        &headers,
        &uri,
        &slug,
        &id,
        &form.csrf,
        Permission::AuditRead,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let verdict = match form.verdict.as_str() {
        v @ ("approve" | "request_changes") => v,
        _ => return (StatusCode::BAD_REQUEST, "invalid verdict").into_response(),
    };
    let note = form.body.trim();
    let note = (!note.is_empty()).then_some(note);
    if let Err(err) = deps
        .db
        .add_change_review(
            &cs.change_id,
            "user",
            Some(session.auth.user_id),
            &session.email,
            verdict,
            note,
        )
        .await
    {
        return internal(err);
    }
    redirect_to_change(&slug, &cs.change_id)
}

/// Withdraws an open draft change request.
///
/// Gated to `registry.configure`. Sets `closed_at`; never touches git, so the
/// draft ref remains promotable.
pub(crate) async fn change_close(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, id)): Path<(String, String)>,
    Form(form): Form<ChangeActionForm>,
) -> Response {
    let (_session, _registry, cs) = match authorize_change_action(
        &deps,
        &headers,
        &uri,
        &slug,
        &id,
        &form.csrf,
        Permission::RegistryConfigure,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if let Err(err) = deps.db.close_changeset(&cs.change_id).await {
        return internal(err);
    }
    redirect_to_change(&slug, &cs.change_id)
}

/// Reopens a closed change request.
///
/// Gated to `registry.configure`. Clears `closed_at`, re-arming the indexer's
/// auto-merge detection.
pub(crate) async fn change_reopen(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, id)): Path<(String, String)>,
    Form(form): Form<ChangeActionForm>,
) -> Response {
    let (_session, _registry, cs) = match authorize_change_action(
        &deps,
        &headers,
        &uri,
        &slug,
        &id,
        &form.csrf,
        Permission::RegistryConfigure,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if let Err(err) = deps.db.reopen_changeset(&cs.change_id).await {
        return internal(err);
    }
    redirect_to_change(&slug, &cs.change_id)
}

#[cfg(test)]
mod tests {
    use axum::http::{header, HeaderMap, HeaderValue};

    use super::{delivery_route_url, request_has_exact_origin, safe_return_path};

    #[test]
    fn login_return_paths_are_same_origin_and_header_safe() {
        assert_eq!(
            safe_return_path(Some(" /-/org/acme/members ")),
            Some("/-/org/acme/members")
        );
        assert_eq!(
            safe_return_path(Some("/invite?secret=opaque")),
            Some("/invite?secret=opaque")
        );

        for unsafe_path in [
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example/",
            "/safe\r\nlocation: https://evil.example/",
            "relative/path",
            "",
        ] {
            assert_eq!(safe_return_path(Some(unsafe_path)), None, "{unsafe_path:?}");
        }
    }

    #[test]
    fn delivery_route_url_preserves_endpoint_scheme_and_effective_port() {
        assert_eq!(
            delivery_route_url("http", "cache.example", 80, "/nix"),
            "http://cache.example/nix",
        );
        assert_eq!(
            delivery_route_url("https", "cache.example", 8443, "/nix"),
            "https://cache.example:8443/nix",
        );
        assert_eq!(
            delivery_route_url("https", "192.0.2.44", 443, "/"),
            "https://192.0.2.44/",
        );
        assert_eq!(
            delivery_route_url("http", "[2001:db8::1]", 8080, "/"),
            "http://[2001:db8::1]:8080/",
        );
    }

    #[test]
    fn session_exchange_requires_the_exact_configured_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://aos.example"),
        );
        assert!(request_has_exact_origin(&headers, "https://aos.example/"));
        assert!(!request_has_exact_origin(
            &headers,
            "https://other.example/"
        ));
        assert!(!request_has_exact_origin(&headers, "http://aos.example/"));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://aos.example.evil"),
        );
        assert!(!request_has_exact_origin(&headers, "https://aos.example/"));
    }
}
