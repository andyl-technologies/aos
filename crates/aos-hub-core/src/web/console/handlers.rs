//! Shared authentication, account-security, and browser-app shell handlers.
//!
//! These transport-neutral `axum` handlers own login, OIDC, device approval,
//! account security, browser-session token exchange, and the authenticated
//! application shell. Resource management is intentionally absent: the
//! browser uses the same generated Connect methods and reviewed plans as the
//! CLI.
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
//!
//! # CSRF
//!
//! Every retained mutating ceremony here is reached with an ambient session
//! cookie, so it is CSRF-able. Each form embeds a per-session synchronizer token
//! ([`mint_csrf_token`](crate::web::csrf::mint_csrf_token)); the handler verifies
//! it ([`check_csrf`]) and answers `403` on a bad or missing token.
//!
//! # Authorization
//!
//! The application shell requires a current session. Resource authorization is
//! performed by each canonical API method after the browser exchanges that
//! session for its short-lived bearer.

use crate::clock::Instant;

use axum::extract::{Form, Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use base64::Engine as _;

use crate::auth::session::{set_cookie_header, ABSOLUTE_LIFETIME_SECS, COOKIE_NAME};
use crate::db::{Database, SessionAuth as DbSession};
use crate::domain::{iam, Principal, Role, Scope};
use crate::web::console::ports::ConsoleDeps;
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
/// The browser console is human-only; an anonymous or invalid cookie is
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

    /// The CSRF synchronizer token bound to this session.
    fn csrf(&self) -> String {
        mint_csrf_token(&self.secret)
    }

    fn api_bearer(&self, deps: &ConsoleDeps) -> anyhow::Result<String> {
        let ttl = self
            .auth
            .expires_at
            .saturating_sub(crate::clock::now_unix_secs())
            .clamp(1, BROWSER_ACCESS_TOKEN_TTL_SECS);
        let token = deps.jwt_keys.mint(
            &crate::db::TokenAuth {
                token_id: format!("browser-session-{}", self.auth.user_id),
                owner: self.principal(),
                scope: Scope::root(),
                permissions: iam::role_grants(Role::Owner).to_vec(),
            },
            ttl,
        )?;
        Ok(format!("Bearer {token}"))
    }
}

/// Lifetime of a bearer minted from an authenticated browser session.
pub(crate) const BROWSER_ACCESS_TOKEN_TTL_SECS: i64 = 300;

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
    let route_permissions = match route_permissions(
        &deps.db,
        &grants,
        headers
            .get("x-aos-console-route")
            .and_then(|value| value.to_str().ok()),
    )
    .await
    {
        Ok(permissions) => permissions,
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
    let body = aos_proto_types::BrowserSessionTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: BROWSER_ACCESS_TOKEN_TTL_SECS,
        principal: Some(aos_proto_types::BrowserSessionPrincipal {
            kind: "user".to_string(),
            id: session.auth.user_id,
            email: session.email,
        }),
        grants: grants
            .into_iter()
            .map(|(scope, role)| aos_proto_types::BrowserSessionGrant {
                scope: scope.as_str().to_string(),
                role: role.as_str().to_string(),
            })
            .collect(),
        route_permissions,
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

async fn route_permissions(
    db: &Database,
    grants: &[(Scope, Role)],
    route: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let Some(route) = route.and_then(aos_hub_console_contract::ConsoleRoute::resolve) else {
        return Ok(Vec::new());
    };
    if matches!(
        route.scope,
        aos_hub_console_contract::ConsoleScope::Organizations
    ) {
        let mut permissions = std::collections::BTreeSet::new();
        for (_, role) in grants {
            permissions.extend(
                iam::role_grants(*role)
                    .iter()
                    .map(|permission| permission.as_str().to_string()),
            );
        }
        return Ok(permissions.into_iter().collect());
    }
    let scope = match route.scope {
        aos_hub_console_contract::ConsoleScope::Instance => Some(Scope::root()),
        aos_hub_console_contract::ConsoleScope::Organizations => None,
        aos_hub_console_contract::ConsoleScope::Organization { slug } => db
            .org_by_slug(&slug)
            .await?
            .map(|org| Scope::parse(&org.stable_id)),
        aos_hub_console_contract::ConsoleScope::Registry { path } => db
            .registry_by_slug(&path)
            .await?
            .map(|registry| Scope::parse(&registry.scope_key)),
        aos_hub_console_contract::ConsoleScope::Cache {
            organization,
            cache,
        } => db
            .binary_cache_by_slug(&format!("{organization}/{cache}"))
            .await?
            .map(|cache| Scope::parse(&cache.scope_key)),
    };
    let Some(scope) = scope else {
        return Ok(Vec::new());
    };
    let Some(context) = db.authorization_context(scope.as_str()).await? else {
        return Ok(Vec::new());
    };
    Ok(iam::role_grants(Role::Owner)
        .iter()
        .copied()
        .filter(|permission| iam::allow(grants, *permission, &context))
        .map(|permission| permission.as_str().to_string())
        .collect())
}

/// Serves the authenticated browser-application shell for a canonical route.
pub(crate) async fn management_app(deps: ConsoleDeps, headers: HeaderMap) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let csrf = html_attribute(&session.csrf());
    let css = crate::web::assets::console_css_name();
    let bootstrap = crate::web::assets::console_bootstrap_name();
    let html = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"aos-session-csrf\" content=\"{csrf}\">\n\
         <title>AOS Hub</title>\n\
         <link rel=\"stylesheet\" href=\"/_assets/{css}\">\n\
         <script type=\"module\" src=\"/_assets/{bootstrap}\"></script>\n\
         </head>\n<body>\n\
         <noscript>The AOS Hub management console requires JavaScript.</noscript>\n\
         </body>\n</html>\n"
    );
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; frame-ancestors 'none'",
            ),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        html,
    )
        .into_response()
}

fn html_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

/// Query carried by a one-time invitation link.
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

/// Exchanges an invitation URL secret for an HttpOnly handoff and renders review.
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
        return sensitive_browser_response(
            Redirect::to(&clean_path).into_response(),
            Some(&invitation_handoff_cookie(token)),
        );
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

/// Accepts the reviewed invitation through the canonical identity service.
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
    let Some(control) = deps.control.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let bearer = match session.api_bearer(&deps) {
        Ok(bearer) => bearer,
        Err(error) => return internal(error),
    };
    match control
        .accept_invitation(
            Some(&bearer),
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

/// Returns a rate-limit response with a bounded positive retry interval.
fn too_many_requests(retry_after: i64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.max(1).to_string())],
        "rate limit exceeded",
    )
        .into_response()
}

/// Resolves the configured browser-session lifetime with a safe default.
async fn effective_session_lifetime(deps: &ConsoleDeps) -> i64 {
    match deps.db.instance_config_get("session_lifetime_secs").await {
        Ok(Some(value)) => value
            .parse::<i64>()
            .ok()
            .filter(|seconds| *seconds > 0)
            .unwrap_or(ABSOLUTE_LIFETIME_SECS),
        _ => ABSOLUTE_LIFETIME_SECS,
    }
}

/// Returns whether the instance permits local password authentication.
async fn password_login_enabled(deps: &ConsoleDeps) -> bool {
    match deps.db.instance_config_get("password_login").await {
        Ok(Some(value)) => !matches!(value.as_str(), "off" | "false" | "0"),
        _ => true,
    }
}
