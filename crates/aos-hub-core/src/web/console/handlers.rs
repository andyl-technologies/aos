//! The shared producer-console request handlers (RFC-0004 Phase 5, stage B).
//!
//! These are the transport- and runtime-neutral `axum` handlers behind the
//! cookie-authenticated producer console: the account profile, passkey
//! management, the org/project dashboards, and the per-registry management
//! pages (tokens, channel rollout, keys, publishes, serving, hosted keys,
//! webhooks, SSO). The page *rendering* lives in
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
//! The only remaining native-only handlers are the git-backed
//! config/change-request flows, which stay in the native hub.
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

use axum::extract::{Form, Path, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use base64::Engine as _;

use crate::auth::session::{set_cookie_header, ABSOLUTE_LIFETIME_SECS, COOKIE_NAME};
use crate::binding::{BindingKind, RuntimeKind};
use crate::config::{self, MembershipChange};
use crate::db::{Database, OrgRecord, RegistryRecord, SessionAuth as DbSession};
use crate::domain::{iam, Permission, Principal, Role, Scope};
use crate::web::console::ports::ConsoleDeps;
use crate::web::console_render as console;
use crate::web::csrf::{connect_or_csrf_ok, mint_csrf_token};
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
    let resolved = match resolve_session_from_headers(&deps.db, headers).await {
        Ok(Some(resolved)) => resolved,
        Ok(None) => return Err(Box::new(Redirect::to("/login").into_response())),
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
        match self.grants(db).await {
            Ok(grants) => iam::allow(&grants, perm, scope),
            Err(_) => false,
        }
    }

    /// The CSRF synchronizer token bound to this session.
    fn csrf(&self) -> String {
        mint_csrf_token(&self.secret)
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
            let scope = Scope::parse(&registry.slug);
            if session_allows_read(deps, headers, &scope).await
                || bearer_allows_read(deps, headers, &scope)
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
    let scope = Scope::parse(&org.slug);
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
    iam::allow(&grants, Permission::Read, scope)
}

/// Whether a bearer JWT in `headers` grants `Read` at `scope`.
fn bearer_allows_read(deps: &ConsoleDeps, headers: &HeaderMap, scope: &Scope) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    match deps.jwt_keys.verify(token) {
        Ok(claims) => iam::token_allows(&claims, Permission::Read, scope),
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
) -> Response {
    let nonce = crate::auth::webauthn::new_challenge();
    let html = console::login_page(None, Some(&nonce), started);
    passkey_html_response(html, &nonce)
}

/// `POST /login` body: the email to send a magic link to.
#[derive(serde::Deserialize)]
pub(crate) struct LoginForm {
    email: String,
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
    if email.is_empty() || !email.contains('@') {
        return Html(console::login_page(
            Some("Enter a valid email address."),
            None,
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
        let start = sso_start_path(&org_slug);
        if enforce_sso {
            return Redirect::to(&start).into_response();
        }
        return Html(console::login_sso_page(&email, &org_slug, &start, started)).into_response();
    }
    let secret = match deps.db.create_magic_link(&email).await {
        Ok(secret) => secret,
        Err(err) => return internal(err),
    };
    let link = format!(
        "{}/auth/magic?token={secret}",
        deps.external_url.trim_end_matches('/'),
    );
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
    // The single generic failure render, used for every rejection path so the
    // endpoint is not an account-existence oracle.
    let invalid = || {
        Html(console::login_page(
            Some("Invalid email or password."),
            None,
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
        Ok(Some(org_slug)) => return Redirect::to(&sso_start_path(&org_slug)).into_response(),
        Ok(None) => {}
        Err(err) => return internal(err),
    }
    // A correct password is a re-authentication: the session is sudo-capable.
    let lifetime = effective_session_lifetime(&deps).await;
    let cookie = match deps.db.create_session(user_id, lifetime, 1).await {
        Ok(secret) => set_cookie_header(&secret, lifetime),
        Err(err) => return internal(err),
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
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
            let Some(org_slug) = Scope::parse(&scope)
                .as_str()
                .split('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
            else {
                continue;
            };
            if !seen_slugs.insert(org_slug.clone()) {
                continue;
            }
            let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
                continue;
            };
            if let Some(config) = deps.db.idp_config(org.id).await? {
                if config.enforce_sso {
                    return Ok(Some(org_slug));
                }
            }
        }
    }
    Ok(None)
}

/// The OIDC start path that redirects a browser into an org's IdP login.
fn sso_start_path(org_slug: &str) -> String {
    format!("/auth/oidc/start?org={}", urlencode(org_slug))
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
    begin_oidc(&deps, &form.org, None, started).await
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
    let target = login
        .redirect_after
        .filter(|p| p.starts_with('/') && !p.starts_with("//"))
        .unwrap_or_else(|| "/".to_string());
    ([(header::SET_COOKIE, cookie)], Redirect::to(&target)).into_response()
}

/// Render a clean SSO error page (no stack traces).
fn sso_error(message: &str, started: Instant) -> Response {
    Html(console::login_page(Some(message), None, started)).into_response()
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
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

/// `GET /logout` — revoke the caller's own session and clear the cookie.
pub(crate) async fn logout(deps: ConsoleDeps, headers: HeaderMap) -> Response {
    if let Some(secret) = crate::web::session::session_secret_from_headers(&headers) {
        if let Err(err) = deps.db.revoke_session(&secret).await {
            return internal(err);
        }
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
                    Json(serde_json::json!({ "redirect": sso_start_path(&org_slug) })),
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
            Ok(req) => req,
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
            if iam::allow(&grants, Permission::Read, &Scope::parse(&org.slug)) {
                orgs.push(org);
            }
        }
        let can_create = may_create_org(&deps.db, &session).await?;
        let is_instance_admin = iam::allow(&grants, Permission::IamAdmin, &Scope::parse(""));
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
        let org_slugs: std::collections::HashMap<i64, String> = deps
            .db
            .list_orgs()
            .await?
            .into_iter()
            .map(|o| (o.id, o.slug))
            .collect();
        let mut rows = Vec::new();
        for c in deps.db.list_caches().await? {
            let org_slug = c
                .org_id
                .and_then(|id| org_slugs.get(&id).cloned())
                .unwrap_or_default();
            let readable = c.visibility == "public"
                || (!org_slug.is_empty()
                    && iam::allow(&grants, Permission::Read, &Scope::parse(&org_slug)));
            if readable {
                rows.push(console::CacheListRow {
                    org_slug,
                    slug: c.slug,
                    name: c.name,
                    visibility: c.visibility,
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
    if iam::allow(&grants, Permission::IamAdmin, &Scope::root()) {
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

/// `GET /-/org/{org}/storage` — the org's storage-bindings tab.
pub(crate) async fn org_storage(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    path: Path<String>,
    pages: Query<DashboardPages>,
) -> Response {
    org_view(deps, headers, started, path, pages, "storage").await
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
    let scope = Scope::parse(&org_slug);
    if !session.allows(&deps.db, Permission::Read, &scope).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let projects = deps.db.list_projects(org.id).await?;
        let bindings = deps.db.list_storage_bindings(org.id).await?;
        let mut caches = Vec::new();
        for c in deps.db.list_caches_for_org(org.id).await? {
            if c.deleted_at.is_some() {
                continue;
            }
            let usage = deps.db.cache_usage(c.id).await?;
            caches.push(console::CacheSummary {
                slug: c.slug,
                name: c.name,
                visibility: c.visibility,
                signed: c.hosted_key_id.is_some(),
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
        let members = load_members(&deps.db, &org_slug).await?;
        let owner_count = members.iter().filter(|m| m.role == "owner").count();
        let can_manage = session
            .allows(&deps.db, Permission::MembersManage, &scope)
            .await;
        let can_audit = session
            .allows(&deps.db, Permission::AuditRead, &scope)
            .await;
        let can_configure = session
            .allows(&deps.db, Permission::RegistryConfigure, &scope)
            .await;
        let can_manage_storage = session
            .allows(&deps.db, Permission::StorageManage, &scope)
            .await;
        let can_delete = session.allows(&deps.db, Permission::IamAdmin, &scope).await;
        Ok::<_, anyhow::Error>(Some(console::org_dashboard(
            &session.email,
            &org,
            &session.csrf(),
            &projects,
            &registries,
            &members,
            &bindings,
            &caches,
            can_manage,
            can_audit,
            can_configure,
            can_manage_storage,
            can_delete,
            owner_count,
            pages.registries(),
            pages.members(),
            active,
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
async fn load_members(db: &Database, org_slug: &str) -> anyhow::Result<Vec<console::MemberRow>> {
    let mut rows = Vec::new();
    for (kind, id, role) in db.list_members_of_scope(org_slug).await? {
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

/// `GET /-/org/{org}/audit` — the org audit feed.
pub(crate) async fn org_audit(
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
    let scope = Scope::parse(&org_slug);
    if !session
        .allows(&deps.db, Permission::AuditRead, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "audit read requires admin").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let rows = deps.db.list_audit(&org_slug).await?;
        Ok::<_, anyhow::Error>(Some(console::audit_page(
            &session.email,
            &org,
            &rows,
            params.page(),
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

/// `POST /-/org/{org}/caches` form: a new managed binary cache.
#[derive(serde::Deserialize)]
pub(crate) struct NewCacheForm {
    #[serde(default)]
    csrf: String,
    slug: String,
    #[serde(default)]
    name: String,
    /// Storage binding (by name) the cache's objects live in.
    binding: String,
    #[serde(default)]
    visibility: String,
    #[serde(default)]
    priority: String,
    #[serde(default)]
    compression: String,
    #[serde(default)]
    want_mass_query: Option<String>,
}

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
    priority: String,
    #[serde(default)]
    compression: String,
    #[serde(default)]
    want_mass_query: Option<String>,
}

/// `POST /-/org/{org}/caches/{slug}/link` form.
#[derive(serde::Deserialize)]
pub(crate) struct CacheLinkForm {
    #[serde(default)]
    csrf: String,
    registry: String,
    #[serde(default)]
    advertised: Option<String>,
    #[serde(default)]
    roots_packages: Option<String>,
}

/// `POST /-/org/{org}/caches/{slug}/unlink` form.
#[derive(serde::Deserialize)]
pub(crate) struct CacheUnlinkForm {
    #[serde(default)]
    csrf: String,
    registry: String,
}

/// `POST /-/org/{org}/caches/{slug}/gc` form.
#[derive(serde::Deserialize)]
pub(crate) struct CacheGcForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    dry_run: Option<String>,
}

/// `POST /-/org/{org}/caches/{slug}/pin/add` form: pin (or renew) a manual GC
/// root.
#[derive(serde::Deserialize)]
pub(crate) struct CachePinAddForm {
    #[serde(default)]
    csrf: String,
    /// The store path to pin: a 32-char hash, a `<hash>-<name>` store name, or a
    /// full `/nix/store/<hash>-<name>` path. Only the hash component is stored.
    #[serde(default)]
    store_hash: String,
    /// Optional expiry, in whole days from now. Empty/zero pins indefinitely.
    #[serde(default)]
    expires_days: String,
}

/// `POST /-/org/{org}/caches/{slug}/pin/remove` form: unpin a manual GC root.
#[derive(serde::Deserialize)]
pub(crate) struct CachePinRemoveForm {
    #[serde(default)]
    csrf: String,
    /// The store-path hash component of the pin to remove.
    #[serde(default)]
    store_hash: String,
}

/// `POST /-/org/{org}/caches/{slug}/delete` form.
#[derive(serde::Deserialize)]
pub(crate) struct CacheConfirmForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    confirm: String,
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

/// Cap on closure nodes walked per pin, mirroring the service's `cache_closure`
/// bound so a pathological closure can't stall a console page render.
const PIN_CLOSURE_NODE_CAP: usize = 10_000;

/// The closure summary for a single pinned root, used to populate a
/// [`console::CachePinRow`].
struct ClosureSummary {
    /// The root object's `<hash>-<name>` store name, or `""` when not indexed.
    store_name: String,
    /// Sum of `file_size` over the present closure nodes (compressed bytes).
    total_size: u64,
    /// Number of present (indexed) closure nodes, including the root.
    count: u64,
    /// Whether the root object itself is present in the cache index.
    present: bool,
}

/// Compute a pinned store path's closure summary by BFS-walking
/// [`crate::db::CacheObject::refs`] from `root_hash`.
///
/// Returns the root's store name plus the closure's total `file_size`, the count
/// of present nodes, and whether the root itself is indexed. A `visited` set
/// keeps each object visited once; the walk is bounded by
/// [`PIN_CLOSURE_NODE_CAP`]. Objects referenced but not present in the index
/// (e.g. not yet uploaded) are skipped from the size/count totals.
///
/// This mirrors the service's `cache_closure` RPC but runs against `deps.db`
/// directly, since the console handlers do not hold a service handle.
///
/// # Errors
///
/// Returns an error on database failure while loading a closure object.
async fn cache_closure_summary(
    db: &crate::db::Database,
    cache_id: i64,
    root_hash: &str,
) -> anyhow::Result<ClosureSummary> {
    use std::collections::{HashSet, VecDeque};
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(root_hash.to_string());
    let mut store_name = String::new();
    let mut total_size: u64 = 0;
    let mut count: u64 = 0;
    let mut present = false;
    while let Some(hash) = queue.pop_front() {
        if visited.len() >= PIN_CLOSURE_NODE_CAP {
            break;
        }
        if !visited.insert(hash.clone()) {
            continue;
        }
        let is_root = hash == root_hash;
        if let Some(object) = db.cache_object(cache_id, &hash).await? {
            if is_root {
                store_name = object.store_name;
                present = true;
            }
            total_size = total_size.saturating_add(object.file_size.max(0) as u64);
            count += 1;
            for r in object.refs {
                if !visited.contains(&r) {
                    queue.push_back(r);
                }
            }
        }
    }
    Ok(ClosureSummary {
        store_name,
        total_size,
        count,
        present,
    })
}

/// Render a cache's detail page (`cache_page`), gathering usage, links, and the
/// org's linkable registries. `notice` surfaces the last action's outcome.
///
/// Returns `404` when the cache is missing or not owned by `org`.
async fn render_cache_detail(
    deps: &ConsoleDeps,
    session: &Session,
    org: &OrgRecord,
    cache: &crate::db::Cache,
    can_admin: bool,
    active: &str,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    let result = async {
        let usage = deps.db.cache_usage(cache.id).await?;
        let binding = match cache.storage_binding_id {
            Some(id) => deps
                .db
                .storage_binding(id)
                .await?
                .map(|b| b.name)
                .unwrap_or_default(),
            None => "default".to_string(),
        };
        let placements =
            placement_overview_rows(deps, crate::db::SurfaceTarget::BinaryCache(cache.id)).await?;
        // The org's storage bindings — targets for the "change storage" control.
        let binding_names: Vec<String> = deps
            .db
            .list_storage_bindings(org.id)
            .await?
            .into_iter()
            .map(|b| b.name)
            .collect();
        let org_registries: Vec<RegistryRecord> = deps
            .db
            .list_registries()
            .await?
            .into_iter()
            .filter(|r| r.org_id == Some(org.id))
            .collect();
        let id_to_reg: std::collections::HashMap<i64, &crate::db::RegistryRecord> =
            org_registries.iter().map(|r| (r.id, r)).collect();
        let mut link_rows = Vec::new();
        let mut linked: std::collections::HashSet<i64> = std::collections::HashSet::new();
        for l in deps.db.list_cache_links(cache.id).await? {
            linked.insert(l.registry_id);
            if let Some(registry) = id_to_reg.get(&l.registry_id) {
                // Surface the same closure-exposure warning the link chokepoint
                // computes, so a risky config (e.g. a private registry rooted
                // into this more-visible cache) is visible at rest, not only at
                // link time.
                let warning = crate::service::assess_cache_link(
                    &cache.slug,
                    &cache.visibility,
                    &registry.slug,
                    &registry.visibility,
                    false,
                    l.roots_packages,
                )
                .warning;
                link_rows.push(console::CacheLinkRow {
                    registry_slug: registry.slug.clone(),
                    roots_packages: l.roots_packages,
                    warning,
                });
            }
        }
        // Linkable registries with visibility, so the form can grey out advertise
        // for one more visible than this cache.
        let linkable: Vec<(String, String)> = org_registries
            .iter()
            .filter(|r| !linked.contains(&r.id))
            .map(|r| (r.slug.clone(), r.visibility.clone()))
            .collect();
        let advertise_frontend = deps.db.cache_advertises_storage_frontend(cache.id).await?;
        // Manual pins (the editor) with each pin's closure summary. Derived
        // roots (release/channel/package_version) are managed elsewhere and are
        // not editable here, so filter to `root_kind == "manual"`. Closure info
        // is admin-only context, so only compute it when the section will render.
        let mut pin_rows = Vec::new();
        if can_admin {
            for root in deps.db.list_cache_roots(cache.id).await? {
                if root.root_kind != "manual" {
                    continue;
                }
                let summary = cache_closure_summary(&deps.db, cache.id, &root.store_hash).await?;
                pin_rows.push(console::CachePinRow {
                    store_hash: root.store_hash,
                    store_name: summary.store_name,
                    closure_size: summary.total_size,
                    closure_count: summary.count,
                    present: summary.present,
                    expires_at: root.expires_at,
                    created_at: root.created_at,
                });
            }
        }
        // Recent GC runs back the GC tab's history; only the GC & pins tab renders
        // them, so only fetch there.
        let gc_runs = if can_admin && active == "pins" {
            deps.db.list_cache_gc_runs(cache.id, 10).await?
        } else {
            Vec::new()
        };
        Ok::<_, anyhow::Error>(console::cache_page(
            &session.email,
            &org.slug,
            &session.csrf(),
            cache,
            &binding,
            &placements,
            &binding_names,
            &usage,
            &link_rows,
            &linkable,
            &pin_rows,
            &gc_runs,
            can_admin,
            advertise_frontend,
            active,
            notice,
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
            read_enabled: placement.effective_read_enabled,
            write_enabled: placement.effective_write_enabled,
        });
    }
    Ok(rows)
}

/// Resolve `(org, cache)` for a cache console route, enforcing that the cache
/// belongs to the org. Returns the deny/redirect response on any failure.
async fn cache_in_org(
    deps: &ConsoleDeps,
    org_slug: &str,
    cache_slug: &str,
) -> Result<(OrgRecord, crate::db::Cache), Response> {
    let Some(org) = deps.db.org_by_slug(org_slug).await.map_err(internal)? else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    let Some(cache) = deps.db.cache_by_slug(cache_slug).await.map_err(internal)? else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    if cache.org_id != Some(org.id) || cache.deleted_at.is_some() {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    Ok((org, cache))
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

/// `GET /-/org/{org}/caches/{slug}/general` — mutable cache policy.
pub(crate) async fn cache_general(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "general").await
}

/// `GET /-/org/{org}/caches/{slug}/links` — the **Linked registries** tab.
pub(crate) async fn cache_links(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "links").await
}

/// `GET /-/org/{org}/caches/{slug}/pins` — the **GC & pins** tab.
pub(crate) async fn cache_pins(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "pins").await
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

/// `GET /-/org/{org}/caches/{slug}/storage` — the **Storage** tab (binding +
/// change storage). The same path's `POST` performs the storage move.
pub(crate) async fn cache_storage_tab(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "storage").await
}

/// `GET /-/org/{org}/caches/{slug}/serving` — the **Serving** tab (bucket-direct
/// frontend advertisement).
pub(crate) async fn cache_serving_tab(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
) -> Response {
    cache_tab(deps, headers, started, org_slug, cache_slug, "serving").await
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
    let scope = Scope::parse(&org_slug);
    if !session.allows(&deps.db, Permission::Read, &scope).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (org, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let can_admin = session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await;
    render_cache_detail(
        &deps, &session, &org, &cache, can_admin, active, None, started,
    )
    .await
}

/// `POST /-/org/{org}/caches` — create a managed binary cache.
pub(crate) async fn org_create_cache(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<NewCacheForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let slug = form.slug.trim();
    if slug.is_empty() {
        return (StatusCode::BAD_REQUEST, "cache slug is required").into_response();
    }
    let Some(visibility) = cache_visibility(&form.visibility) else {
        return (StatusCode::BAD_REQUEST, "invalid visibility").into_response();
    };
    let priority = form.priority.trim().parse::<i64>().unwrap_or(40);
    let compression = match form.compression.trim() {
        "" | "zstd" => "zstd",
        "xz" => "xz",
        "none" => "none",
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid compression '{other}'"),
            )
                .into_response()
        }
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        // An empty binding selects the deployment's default storage; otherwise
        // resolve the named binding.
        let binding_id = if form.binding.trim().is_empty() {
            None
        } else {
            match deps
                .db
                .storage_binding_by_name(org.id, form.binding.trim())
                .await?
            {
                Some(b) => Some(b.id),
                None => return Ok(Some(Err("unknown storage binding".to_string()))),
            }
        };
        let name = if form.name.trim().is_empty() {
            slug
        } else {
            form.name.trim()
        };
        match deps
            .db
            .create_cache(
                Some(org.id),
                slug,
                name,
                binding_id,
                "",
                None,
                visibility,
                priority,
                compression,
                form.want_mass_query.is_some(),
            )
            .await
        {
            Ok(_) => {}
            Err(e) => return Ok(Some(Err(format!("{e:#}")))),
        }
        deps.db
            .record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "cache.create",
                &org_slug,
                None,
                None,
                None,
                Some(slug),
            )
            .await?;
        Ok::<_, anyhow::Error>(Some(Ok(())))
    }
    .await;
    match result {
        Ok(Some(Ok(()))) => {
            Redirect::to(&format!("/-/org/{org_slug}/caches/{slug}")).into_response()
        }
        Ok(Some(Err(msg))) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/caches/{slug}/general` — update mutable cache policy.
pub(crate) async fn cache_update(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (_, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
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
    let priority = form
        .priority
        .trim()
        .parse::<i64>()
        .unwrap_or(cache.priority);
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
    let result = deps
        .db
        .update_cache(
            cache.id,
            &name,
            visibility,
            priority,
            &compression,
            form.want_mass_query.is_some(),
            cache.hosted_key_id,
        )
        .await;
    match result {
        Ok(_) => {
            Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/general")).into_response()
        }
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/caches/{slug}/link` — link a registry to the cache.
pub(crate) async fn cache_link(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CacheLinkForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (org, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let result = async {
        let Some(registry) = deps.db.registry_by_slug(form.registry.trim()).await? else {
            return Ok(Some("unknown registry".to_string()));
        };
        if registry.org_id != Some(org.id) {
            return Ok(Some("registry is not in this organization".to_string()));
        }
        // Same cross-visibility policy the RPC enforces (single chokepoint): a
        // cache advertised on a more-visible registry is refused here too,
        // rather than being silently written and then handing consumers an
        // unreadable substituter. The closure-exposure warning is non-blocking
        // and is surfaced persistently on the cache page.
        let advisory = crate::service::assess_cache_link(
            &cache.slug,
            &cache.visibility,
            &registry.slug,
            &registry.visibility,
            form.advertised.is_some(),
            form.roots_packages.is_some(),
        );
        if let Some(reject) = advisory.reject {
            return Ok(Some(reject));
        }
        deps.db
            .link_cache(
                cache.id,
                registry.id,
                form.roots_packages.is_some(),
                form.advertised.is_some(),
            )
            .await?;
        // A link is an operational association only — advertising the cache to
        // consumers is an explicit edit of the registry's committed `[[caches]]`
        // (Settings -> Config), never a write-through from linking.
        Ok::<_, anyhow::Error>(None)
    }
    .await;
    match result {
        Ok(None) => {
            Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/links")).into_response()
        }
        Ok(Some(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/caches/{slug}/storage` form: the target binding.
#[derive(serde::Deserialize)]
pub(crate) struct CacheStorageForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    binding: String,
}

/// `POST /-/org/{org}/caches/{slug}/storage` — migrate a cache's surface to a
/// different storage backend (copy every object, re-point, reconcile the index).
pub(crate) async fn cache_change_storage(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CacheStorageForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (org, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let result = async {
        let new_binding_id =
            match resolve_target_binding(&deps, Some(org.id), &form.binding).await? {
                Ok(id) => id,
                Err(msg) => return Ok(Some(msg)),
            };
        match crate::migrate::migrate_cache_storage(
            &deps.db,
            deps.surface.as_ref(),
            deps.surface_write.as_ref(),
            &cache,
            new_binding_id,
        )
        .await
        {
            Ok(_) => Ok(None),
            Err(err) => Ok(Some(format!("{err:#}"))),
        }
    }
    .await;
    match result {
        Ok(None) => {
            Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/storage")).into_response()
        }
        Ok(Some(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/caches/{slug}/advertise-frontend` form: the checkbox.
#[derive(serde::Deserialize)]
pub(crate) struct CacheAdvertiseFrontendForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    advertise: Option<String>,
}

/// `POST /-/org/{org}/caches/{slug}/advertise-frontend` — toggle whether the
/// cache advertises its inherited storage-binding frontend (RFC-0004 §12).
pub(crate) async fn cache_set_advertise_frontend(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CacheAdvertiseFrontendForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (_org, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    if let Err(err) = deps
        .db
        .set_cache_advertise_storage_frontend(cache.id, form.advertise.is_some())
        .await
    {
        return internal(err);
    }
    Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/serving")).into_response()
}

/// `POST /-/org/{org}/caches/{slug}/unlink` — remove a cache⇄registry link.
pub(crate) async fn cache_unlink(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CacheUnlinkForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (_, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let result = async {
        if let Some(registry) = deps.db.registry_by_slug(form.registry.trim()).await? {
            deps.db.unlink_cache(cache.id, registry.id).await?;
            // Unlinking only drops the operational association; the committed
            // `[[caches]]` config is edited explicitly via Settings -> Config.
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => {
            Redirect::to(&format!("/-/org/{org_slug}/caches/{cache_slug}/links")).into_response()
        }
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/caches/{slug}/gc` — sweep the cache (dry run or delete).
pub(crate) async fn cache_gc(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CacheGcForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (org, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let dry_run = form.dry_run.is_some();
    let now = crate::clock::now_unix_secs();
    let notice =
        match crate::gc::sweep_cache(&deps.db, deps.surface_write.as_ref(), &cache, dry_run, now)
            .await
        {
            Ok(stats) => {
                let freed = crate::web::render::human_size(stats.freed_bytes.max(0) as u64);
                if dry_run {
                    format!(
                        "Dry run: {} of {} objects collectable, {} reclaimable.",
                        stats.deleted_objects, stats.scanned, freed
                    )
                } else {
                    format!(
                        "Collected {} objects, reclaimed {} ({} retained).",
                        stats.deleted_objects, freed, stats.retained
                    )
                }
            }
            Err(err) => format!("GC failed: {err:#}"),
        };
    render_cache_detail(
        &deps,
        &session,
        &org,
        &cache,
        true,
        "pins",
        Some(&notice),
        started,
    )
    .await
}

/// Extract the store-path hash component from operator-entered text.
///
/// Accepts a bare 32-char hash, a `<hash>-<name>` store name, or a full
/// `/nix/store/<hash>-<name>` path, returning just the hash. A trailing
/// `.narinfo`/`.nar` suffix is tolerated. Returns `None` when no plausible hash
/// remains after trimming.
fn normalize_store_hash(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    // Drop a leading store path, keeping the basename.
    if let Some(idx) = s.rfind('/') {
        s = &s[idx + 1..];
    }
    // Drop common narinfo/nar suffixes.
    if let Some(stripped) = s.strip_suffix(".narinfo") {
        s = stripped;
    } else if let Some(stripped) = s.strip_suffix(".nar") {
        s = stripped;
    }
    // The hash is the component before the first `-` of `<hash>-<name>`.
    let hash = s.split('-').next().unwrap_or(s).trim();
    if hash.is_empty() {
        None
    } else {
        Some(hash.to_string())
    }
}

/// `POST /-/org/{org}/caches/{slug}/pin/add` — pin (or renew) a manual GC root.
///
/// Parses the store hash (a bare hash, `<hash>-<name>`, or full store path) and
/// an optional `expires_days`, computing `expires_at = now + days*86400`
/// (empty/zero pins indefinitely). Re-pinning an existing hash renews it in
/// place, since `pin_cache_path` upserts.
pub(crate) async fn cache_pin_add(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CachePinAddForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (org, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let Some(store_hash) = normalize_store_hash(&form.store_hash) else {
        return (StatusCode::BAD_REQUEST, "a store hash is required").into_response();
    };
    // Empty `expires_days` = unlimited; a positive integer sets a deadline.
    let expires_at = match form.expires_days.trim() {
        "" => None,
        other => match other.parse::<i64>() {
            Ok(days) if days > 0 => Some(crate::clock::now_unix_secs() + days * 86_400),
            Ok(_) => None,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "expires must be a whole number of days",
                )
                    .into_response()
            }
        },
    };
    let notice = match deps
        .db
        .pin_cache_path(cache.id, &store_hash, expires_at)
        .await
    {
        Ok(()) => match expires_at {
            Some(_) => format!("Pinned {store_hash} (expires set)."),
            None => format!("Pinned {store_hash} (unlimited)."),
        },
        Err(err) => format!("Pin failed: {err:#}"),
    };
    render_cache_detail(
        &deps,
        &session,
        &org,
        &cache,
        true,
        "pins",
        Some(&notice),
        started,
    )
    .await
}

/// `POST /-/org/{org}/caches/{slug}/pin/remove` — remove a manual GC pin.
///
/// Unpins the given store hash; if no manual pin existed the notice says so.
pub(crate) async fn cache_pin_remove(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CachePinRemoveForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (org, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let Some(store_hash) = normalize_store_hash(&form.store_hash) else {
        return (StatusCode::BAD_REQUEST, "a store hash is required").into_response();
    };
    let notice = match deps.db.unpin_cache_path(cache.id, &store_hash).await {
        Ok(true) => format!("Unpinned {store_hash}."),
        Ok(false) => format!("No manual pin for {store_hash}."),
        Err(err) => format!("Unpin failed: {err:#}"),
    };
    render_cache_detail(
        &deps,
        &session,
        &org,
        &cache,
        true,
        "pins",
        Some(&notice),
        started,
    )
    .await
}

/// `POST /-/org/{org}/caches/{slug}/delete` — soft-delete a cache (typed slug
/// confirmation).
pub(crate) async fn cache_delete(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path((org_slug, cache_slug)): Path<(String, String)>,
    Form(form): Form<CacheConfirmForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let (_, cache) = match cache_in_org(&deps, &org_slug, &cache_slug).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    if form.confirm.trim() != cache_slug {
        return (StatusCode::BAD_REQUEST, "type the cache slug to confirm").into_response();
    }
    // A 30-day grace window before the cache's objects are eligible for purge,
    // mirroring the org soft-delete.
    let purge_after = crate::clock::now_unix_secs() + 30 * 86_400;
    let result = async {
        deps.db.soft_delete_cache(cache.id, purge_after).await?;
        deps.db
            .record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "cache.delete",
                &org_slug,
                None,
                None,
                None,
                Some(&cache_slug),
            )
            .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => Redirect::to(&format!("/-/org/{org_slug}/caches")).into_response(),
        Err(err) => internal(err),
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

/// Checks the [`config::change_membership`] privilege ceiling for a grant.
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
    let actor_rank = db
        .effective_scopes(*actor)
        .await?
        .into_iter()
        .filter(|(grant_scope, _)| grant_scope.contains(scope))
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
    email: String,
    role: String,
}

/// `POST /-/org/{org}/members` — invite a member through a change-set.
pub(crate) async fn org_invite_member(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    let scope = Scope::parse(&org_slug);
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    let Some(role) = Role::parse(&form.role) else {
        return (StatusCode::BAD_REQUEST, "unknown role").into_response();
    };
    let email = form.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return (StatusCode::BAD_REQUEST, "invalid email").into_response();
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            anyhow::bail!("no org");
        };
        let invitee = deps.db.find_or_create_user(&email).await?;
        let target = Principal::user(invitee);
        if let Err(reject) =
            membership_grant_allowed(&deps.db, &session.principal(), &target, &scope, role).await?
        {
            return Ok(Err(reject));
        }
        config::change_membership(
            &deps.db,
            &session.principal(),
            &session.email,
            MembershipChange::Grant,
            &target,
            &scope,
            role,
        )
        .await?;
        // The grant is committed; now notify the invitee. Mint a single-use
        // magic link (same construction as the login handler) so the email
        // carries a working sign-in URL to the console, and render the shared
        // invite copy. Delivery failure must NOT fail the invite — the role
        // grant already stands and the person can still sign in normally — so a
        // send error is logged and swallowed rather than propagated.
        match deps.db.create_magic_link(&email).await {
            Ok(secret) => {
                let link = format!(
                    "{}/auth/magic?token={secret}",
                    deps.external_url.trim_end_matches('/'),
                );
                let content =
                    crate::email::invite_email(console::brand(), &org.slug, role.as_str(), &link);
                if let Err(err) = deps.mailer.send_email(&email, &content).await {
                    tracing::warn!(error = %format!("{err:#}"), "invite email delivery failed");
                }
            }
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "invite magic-link creation failed");
            }
        }
        Ok::<Result<(), MembershipReject>, anyhow::Error>(Ok(()))
    }
    .await;
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}/members")).into_response(),
        Ok(Err(reject)) => reject.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/members/remove` form.
#[derive(serde::Deserialize)]
pub(crate) struct RemoveForm {
    #[serde(default)]
    csrf: String,
    principal_kind: String,
    principal_id: i64,
}

/// `POST /-/org/{org}/members/remove` — revoke a member through a change-set.
pub(crate) async fn org_remove_member(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<RemoveForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    let Some(kind) = crate::domain::PrincipalKind::parse(&form.principal_kind) else {
        return (StatusCode::BAD_REQUEST, "unknown principal kind").into_response();
    };
    let result = async {
        let members = deps.db.list_members_of_scope(&org_slug).await?;
        let owners: Vec<_> = members.iter().filter(|(_, _, r)| r == "owner").collect();
        let target_is_owner = members.iter().any(|(k, id, r)| {
            k == &form.principal_kind && *id == form.principal_id && r == "owner"
        });
        if target_is_owner && owners.len() <= 1 {
            return Ok(Err(()));
        }
        config::change_membership(
            &deps.db,
            &session.principal(),
            &session.email,
            MembershipChange::Revoke,
            &Principal {
                kind,
                id: form.principal_id,
            },
            &scope,
            Role::Viewer,
        )
        .await?;
        Ok::<Result<(), ()>, anyhow::Error>(Ok(()))
    }
    .await;
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}/members")).into_response(),
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

/// `POST /-/org/{org}/members/role` form: a principal and its new role.
#[derive(serde::Deserialize)]
pub(crate) struct RoleForm {
    #[serde(default)]
    csrf: String,
    principal_kind: String,
    principal_id: i64,
    role: String,
}

/// `POST /-/org/{org}/members/role` — change a member's role.
pub(crate) async fn org_member_role(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<RoleForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    let Some(kind) = crate::domain::PrincipalKind::parse(&form.principal_kind) else {
        return (StatusCode::BAD_REQUEST, "unknown principal kind").into_response();
    };
    let Some(role) = Role::parse(&form.role) else {
        return (StatusCode::BAD_REQUEST, "unknown role").into_response();
    };
    let target = Principal {
        kind,
        id: form.principal_id,
    };
    let result = async {
        if let Err(reject) =
            membership_grant_allowed(&deps.db, &session.principal(), &target, &scope, role).await?
        {
            return Ok(Err(reject));
        }
        let members = deps.db.list_members_of_scope(&org_slug).await?;
        let owners = members.iter().filter(|(_, _, r)| r == "owner").count();
        let target_is_last_owner = role != Role::Owner
            && owners <= 1
            && members.iter().any(|(k, id, r)| {
                k == &form.principal_kind && *id == form.principal_id && r == "owner"
            });
        if target_is_last_owner {
            return Ok(Err(MembershipReject::LastOwner));
        }
        config::change_membership(
            &deps.db,
            &session.principal(),
            &session.email,
            MembershipChange::Grant,
            &target,
            &scope,
            role,
        )
        .await?;
        Ok::<Result<(), MembershipReject>, anyhow::Error>(Ok(()))
    }
    .await;
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}/members")).into_response(),
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
    slug: String,
    name: String,
}

/// `POST /new` — create an org and auto-grant the caller `Owner`.
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
    let result = async {
        if deps.db.org_by_slug_including_deleted(slug).await?.is_some() {
            return Ok(Err("That slug is already taken."));
        }
        deps.db.create_org(slug, name).await?;
        deps.db
            .grant_membership("user", session.auth.user_id, slug, Role::Owner.as_str())
            .await?;
        deps.db
            .record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "org.create",
                slug,
                None,
                None,
                None,
                Some(name),
            )
            .await?;
        Ok::<Result<(), &str>, anyhow::Error>(Ok(()))
    }
    .await;
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{slug}")).into_response(),
        Ok(Err(message)) => reject(message),
        Err(err) => internal(err),
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

/// `POST /-/org/{org}/projects` form: a materialized path and a display name.
#[derive(serde::Deserialize)]
pub(crate) struct NewProjectForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    path: String,
    name: String,
}

/// `POST /-/org/{org}/projects` — create a project under an org.
pub(crate) async fn org_create_project(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<NewProjectForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let name = form.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "project name is required").into_response();
    }
    let path = form.path.trim().trim_matches('/');
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(false);
        };
        deps.db.create_project(org.id, path, name).await?;
        deps.db
            .record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "project.create",
                &org_slug,
                None,
                None,
                None,
                Some(name),
            )
            .await?;
        Ok::<_, anyhow::Error>(true)
    }
    .await;
    match result {
        Ok(true) => Redirect::to(&format!("/-/org/{org_slug}/projects")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

/// `POST /-/org/{org}/projects/delete` / `bindings/delete` form: a row id.
#[derive(serde::Deserialize)]
pub(crate) struct DeleteByIdForm {
    #[serde(default)]
    csrf: String,
    id: i64,
}

/// `POST /-/org/{org}/projects/delete` — delete an empty project.
pub(crate) async fn org_delete_project(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<DeleteByIdForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let Some(project) = deps
            .db
            .list_projects(org.id)
            .await?
            .into_iter()
            .find(|p| p.id == form.id)
        else {
            return Ok(Some(Err("no such project")));
        };
        let in_use = deps
            .db
            .list_registries()
            .await?
            .into_iter()
            .any(|r| r.org_id == Some(org.id) && r.project_path == project.path);
        if in_use {
            return Ok(Some(Err("project still has registries")));
        }
        deps.db.delete_project(org.id, project.id).await?;
        deps.db
            .record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "project.delete",
                &org_slug,
                None,
                None,
                None,
                Some(&project.path),
            )
            .await?;
        Ok::<_, anyhow::Error>(Some(Ok(())))
    }
    .await;
    match result {
        Ok(Some(Ok(()))) => Redirect::to(&format!("/-/org/{org_slug}/projects")).into_response(),
        Ok(Some(Err(msg))) => (StatusCode::CONFLICT, msg).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/bindings/delete` — delete an unused storage binding.
pub(crate) async fn org_delete_binding(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<DeleteByIdForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&deps, &session, &scope, Permission::StorageManage).await {
        return *deny;
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let Some(binding) = deps
            .db
            .list_storage_bindings(org.id)
            .await?
            .into_iter()
            .find(|b| b.id == form.id)
        else {
            return Ok(Some(Err("no such binding")));
        };
        let used_by_registry = deps
            .db
            .list_registries()
            .await?
            .into_iter()
            .any(|r| r.storage_binding_id == Some(binding.id));
        if used_by_registry {
            return Ok(Some(Err("binding still in use by a registry")));
        }
        // Caches reference bindings too — deleting one a cache depends on would
        // orphan that cache's storage, so guard it the same way.
        let used_by_cache = deps
            .db
            .list_caches()
            .await?
            .into_iter()
            .any(|c| c.deleted_at.is_none() && c.storage_binding_id == Some(binding.id));
        if used_by_cache {
            return Ok(Some(Err("binding still in use by a cache")));
        }
        deps.db.delete_storage_binding(org.id, binding.id).await?;
        deps.db
            .record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "binding.delete",
                &org_slug,
                None,
                None,
                None,
                Some(&binding.name),
            )
            .await?;
        Ok::<_, anyhow::Error>(Some(Ok(())))
    }
    .await;
    match result {
        Ok(Some(Ok(()))) => Redirect::to(&format!("/-/org/{org_slug}/storage")).into_response(),
        Ok(Some(Err(msg))) => (StatusCode::CONFLICT, msg).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/bindings` form: a name, a backend `kind`, and a root.
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
    /// Access key id for a private `s3`/`r2` binding.
    #[serde(default)]
    access_key_id: String,
    /// Secret access key for a private `s3`/`r2` binding.
    #[serde(default)]
    secret_access_key: String,
}

/// `POST /-/org/{org}/bindings` — create a storage binding.
pub(crate) async fn org_create_binding(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&deps, &session, &scope, Permission::StorageManage).await {
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
    let kind_str = form.kind.trim();
    let kind_str = if kind_str.is_empty() {
        "local_fs"
    } else {
        kind_str
    };
    let Some(kind) = BindingKind::parse(kind_str) else {
        return (
            StatusCode::BAD_REQUEST,
            format!("unknown storage binding kind '{kind_str}' (expected local_fs, s3, or r2)"),
        )
            .into_response();
    };
    // The serving runtime gates which kinds are usable; `current()` reflects
    // this process (native hub vs. Worker). The Worker has no filesystem, so it
    // rejects local_fs; both runtimes accept s3/r2 (served via presigned URLs).
    let runtime = RuntimeKind::current();
    if !runtime.supports(kind) {
        let supported = runtime
            .supported_binding_kinds()
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "storage binding kind '{kind_str}' is not supported on the {} runtime; \
                 supported kinds: [{supported}]",
                runtime.name(),
            ),
        )
            .into_response();
    }
    let origin = if kind.requires_origin_config() {
        Some(crate::binding_provision::OriginInput {
            endpoint: form.endpoint.trim(),
            region: form.region.trim(),
            access_key_id: form.access_key_id.trim(),
            secret_access_key: form.secret_access_key.trim(),
            private: form.access.trim() != "public",
        })
    } else {
        None
    };
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let id = crate::binding_provision::provision_binding(
            &deps.db,
            deps.sealer.as_ref(),
            crate::binding_provision::NewBinding {
                org_id: org.id,
                name,
                kind,
                root,
                origin,
            },
        )
        .await?;
        deps.db
            .record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "binding.create",
                &org_slug,
                None,
                None,
                None,
                Some(name),
            )
            .await?;
        Ok::<_, crate::binding_provision::ProvisionError>(Some(id))
    }
    .await;
    match result {
        Ok(Some(_)) => Redirect::to(&format!("/-/org/{org_slug}/storage")).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(crate::binding_provision::ProvisionError::AlreadyExists(_)) => (
            StatusCode::CONFLICT,
            format!("a storage binding named '{name}' already exists"),
        )
            .into_response(),
        Err(crate::binding_provision::ProvisionError::Invalid(m)) => {
            (StatusCode::BAD_REQUEST, m).into_response()
        }
        Err(crate::binding_provision::ProvisionError::Backend(err)) => {
            (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response()
        }
    }
}

/// `GET /-/org/{org}/bindings/{id}` — a custom storage binding's serving page
/// (public access + frontends), RFC-0004 §12.
pub(crate) async fn org_binding(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, binding_id)): Path<(String, i64)>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&deps, &session, &scope, Permission::StorageManage).await {
        return *deny;
    }
    org_binding_view(&deps, &session, &org_slug, binding_id, None, started).await
}

/// Render an org binding's serving page (or `404` when the binding is not the
/// org's). Shared by the GET page and the POST action's re-render.
async fn org_binding_view(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    binding_id: i64,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    let org = match deps.db.org_by_slug(org_slug).await {
        Ok(Some(o)) => o,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    let binding = match deps.db.storage_binding(binding_id).await {
        Ok(Some(b)) if b.org_id == Some(org.id) => b,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    let frontends = match deps.db.list_storage_frontends(binding_id).await {
        Ok(f) => f,
        Err(err) => return internal(err),
    };
    Html(console::org_binding_page(
        &session.email,
        org_slug,
        &binding,
        &frontends,
        &session.csrf(),
        notice,
        started,
    ))
    .into_response()
}

/// `POST /-/org/{org}/bindings/{id}` — manage a custom binding's public access
/// and frontends (`op`: `set-public` / `add-frontend` / `delete-frontend`).
pub(crate) async fn org_binding_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path((org_slug, binding_id)): Path<(String, i64)>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let field = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, field("csrf")) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&deps, &session, &scope, Permission::StorageManage).await {
        return *deny;
    }
    // The binding must belong to this org.
    let org = match deps.db.org_by_slug(&org_slug).await {
        Ok(Some(o)) => o,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    match deps.db.storage_binding(binding_id).await {
        Ok(Some(b)) if b.org_id == Some(org.id) => {}
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    }
    let outcome: Result<&str, String> = match field("op") {
        "set-public" => {
            let url = field("endpoint").trim();
            let url = (!url.is_empty()).then_some(url);
            deps.db
                .set_binding_public(binding_id, field("access"), url)
                .await
                .map(|_| "Public access saved.")
                .map_err(|e| format!("{e:#}"))
        }
        "add-frontend" => {
            let priority: i64 = field("consumer_priority").trim().parse().unwrap_or(100);
            deps.db
                .create_storage_frontend(
                    binding_id,
                    field("domain").trim(),
                    field("base_path").trim(),
                    if field("mode") == "proxied" {
                        "proxied"
                    } else {
                        "direct"
                    },
                    field("serves_git") == "1",
                    field("serves_cache") == "1",
                    field("serves_web") == "1",
                    priority,
                    field("advertised") == "1",
                )
                .await
                .map(|_| "Frontend added.")
                .map_err(|e| format!("{e:#}"))
        }
        "edit-frontend" => {
            let Ok(id) = field("id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad frontend id").into_response();
            };
            match deps.db.list_storage_frontends(binding_id).await {
                Ok(list) if list.iter().any(|f| f.id == id) => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such frontend").into_response(),
                Err(err) => return internal(err),
            }
            let priority: i64 = field("consumer_priority").trim().parse().unwrap_or(100);
            deps.db
                .update_frontend(
                    id,
                    field("domain").trim(),
                    field("base_path").trim(),
                    if field("mode") == "proxied" {
                        "proxied"
                    } else {
                        "direct"
                    },
                    field("serves_git") == "1",
                    field("serves_cache") == "1",
                    field("serves_web") == "1",
                    priority,
                    field("advertised") == "1",
                )
                .await
                .map(|_| "Frontend updated.")
                .map_err(|e| format!("{e:#}"))
        }
        "delete-frontend" => {
            let Ok(id) = field("id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad frontend id").into_response();
            };
            match deps.db.list_storage_frontends(binding_id).await {
                Ok(list) if list.iter().any(|f| f.id == id) => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such frontend").into_response(),
                Err(err) => return internal(err),
            }
            deps.db
                .delete_frontend(id)
                .await
                .map(|_| "Frontend deleted.")
                .map_err(|e| format!("{e:#}"))
        }
        _ => return (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    };
    let notice = match outcome {
        Ok(n) => n,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    org_binding_view(
        &deps,
        &session,
        &org_slug,
        binding_id,
        Some(notice),
        started,
    )
    .await
}

/// `GET /-/org/{org}/registries/new` — the create-registry form.
pub(crate) async fn org_new_registry_form(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(None);
        };
        let projects = deps.db.list_projects(org.id).await?;
        let bindings = deps.db.list_storage_bindings(org.id).await?;
        Ok::<_, anyhow::Error>(Some(console::new_registry_page(
            &session.email,
            &org,
            &session.csrf(),
            &projects,
            &bindings,
            None,
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

/// `POST /-/org/{org}/registries` form: the new managed registry's fields.
#[derive(serde::Deserialize)]
pub(crate) struct NewRegistryForm {
    #[serde(default)]
    csrf: String,
    name: String,
    #[serde(default)]
    project_path: String,
    binding: String,
    #[serde(default)]
    visibility: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    trust_keys: String,
    #[serde(default)]
    require_signatures: Option<String>,
}

/// `POST /-/org/{org}/registries` — create a managed registry.
pub(crate) async fn org_create_registry(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    Form(form): Form<NewRegistryForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let Some(org) = (match deps.db.org_by_slug(&org_slug).await {
        Ok(org) => org,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    async fn reject(
        deps: &ConsoleDeps,
        org: &OrgRecord,
        session: &Session,
        message: &str,
        started: Instant,
    ) -> Response {
        let projects = deps.db.list_projects(org.id).await.unwrap_or_default();
        let bindings = deps
            .db
            .list_storage_bindings(org.id)
            .await
            .unwrap_or_default();
        Html(console::new_registry_page(
            &session.email,
            org,
            &session.csrf(),
            &projects,
            &bindings,
            Some(message),
            started,
        ))
        .into_response()
    }

    let name = form.name.trim();
    if name.is_empty() {
        return reject(&deps, &org, &session, "Registry name is required.", started).await;
    }
    let visibility = match form.visibility.trim() {
        "" => "private",
        v @ ("public" | "internal" | "private") => v,
        _ => return reject(&deps, &org, &session, "Invalid visibility.", started).await,
    };
    // An empty binding selection means "default storage" (binding_id None):
    // the registry roots on the deployment's own storage, addressed by its
    // prefix. A non-empty name must resolve to one of the org's bindings.
    let binding_name = form.binding.trim();
    let binding_id = if binding_name.is_empty() {
        None
    } else {
        match deps.db.storage_binding_by_name(org.id, binding_name).await {
            Ok(Some(b)) => Some(b.id),
            Ok(None) => {
                return reject(
                    &deps,
                    &org,
                    &session,
                    &format!("No storage binding '{binding_name}' in this org."),
                    started,
                )
                .await
            }
            Err(err) => return internal(err),
        }
    };
    let project_path = form.project_path.trim().trim_matches('/');
    let prefix = form.prefix.trim();
    let trust_keys: Vec<String> = form
        .trust_keys
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let require_signatures = form.require_signatures.is_some();

    let created = deps
        .db
        .create_managed_registry(
            org.id,
            project_path,
            name,
            visibility,
            binding_id,
            prefix,
            &trust_keys,
            require_signatures,
        )
        .await;
    match created {
        Ok(_) => {}
        Err(err) => return reject(&deps, &org, &session, &format!("{err:#}"), started).await,
    }
    let canonical = match deps
        .db
        .registry_by_scope(&org.slug, project_path, name)
        .await
    {
        Ok(Some(reg)) => reg.slug,
        Ok(None) => return internal(anyhow::anyhow!("registry vanished after creation")),
        Err(err) => return internal(err),
    };
    if let Err(err) = deps
        .db
        .record_audit(
            "user",
            Some(session.auth.user_id),
            &session.email,
            "registry.create",
            &canonical,
            None,
            None,
            None,
            Some(visibility),
        )
        .await
    {
        return internal(err);
    }
    Redirect::to(&format!("/{canonical}/")).into_response()
}

/// `POST /-/org/{org}/delete` form: the typed-confirmation slug.
#[derive(serde::Deserialize)]
pub(crate) struct OrgDeleteForm {
    #[serde(default)]
    csrf: String,
    confirm: String,
}

/// Soft-delete grace window: 30 days (matches the offboarding default).
const ORG_DELETE_GRACE_SECS: i64 = 30 * 24 * 60 * 60;

/// `POST /-/org/{org}/delete` — soft-delete an org behind a typed confirmation.
pub(crate) async fn org_delete(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&deps, &session, &scope, Permission::IamAdmin).await {
        return *deny;
    }
    if form.confirm.trim() != org_slug {
        return (
            StatusCode::BAD_REQUEST,
            "type the organization slug to confirm",
        )
            .into_response();
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(false);
        };
        let deleted = deps
            .db
            .soft_delete_org(org.id, ORG_DELETE_GRACE_SECS)
            .await?;
        if deleted {
            deps.db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "org.delete",
                    &org_slug,
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
        }
        Ok::<_, anyhow::Error>(deleted)
    }
    .await;
    match result {
        Ok(_) => Redirect::to("/-/orgs").into_response(),
        Err(err) => internal(err),
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
    render_instance(deps, session, "general", notice, started).await
}

/// Renders one instance-settings tab (`general` / `branding` / `serving` /
/// `storage`), instance-admin gated. All but storage load and render the
/// editable [`InstanceSettings`](crate::db::InstanceSettings) bundle.
async fn render_instance(
    deps: &ConsoleDeps,
    session: &Session,
    active: &str,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    if !session
        .allows(&deps.db, Permission::IamAdmin, &Scope::parse(""))
        .await
    {
        return (StatusCode::FORBIDDEN, "instance admin required").into_response();
    }
    if active == "storage" {
        let binding = match deps.db.instance_default_binding().await {
            Ok(b) => b,
            Err(err) => return internal(err),
        };
        let frontends = match &binding {
            Some(b) => match deps.db.list_storage_frontends(b.id).await {
                Ok(f) => f,
                Err(err) => return internal(err),
            },
            None => Vec::new(),
        };
        return Html(console::instance_storage_page(
            &session.email,
            deps.default_storage_location.as_deref(),
            binding.as_ref(),
            &frontends,
            &session.csrf(),
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
        "serving" => {
            console::instance_serving_page(&session.email, &csrf, &settings, notice, started)
        }
        _ => console::instance_settings_page(&session.email, &csrf, &settings, notice, started),
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
        .allows(&deps.db, Permission::IamAdmin, &Scope::parse(""))
        .await
    {
        return Err((StatusCode::FORBIDDEN, "instance admin required").into_response());
    }
    Ok(session)
}

/// `GET /-/instance/storage` — the instance default-storage page (read-only).
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

/// `GET /-/instance/serving` — the serving-defaults tab (instance admins only).
pub(crate) async fn instance_serving(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_instance(&deps, &session, "serving", None, started).await
}

/// `POST /-/instance` form: signup + identity policy.
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
    caches_public: Option<String>,
    #[serde(default)]
    session_lifetime_secs: String,
}

/// `POST /-/instance` — update signup + identity policy (instance admins).
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
    let policy = crate::db::SignupPolicy::parse(&form.signup_policy);
    let result = async {
        deps.db.set_signup_policy(policy).await?;
        // Normalize the allowlist to lowercased, comma-joined domains.
        let domains: Vec<String> = form
            .signup_domains
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase())
            .collect();
        deps.db
            .set_instance_config("signup_domains", Some(&domains.join(",")))
            .await?;
        deps.db
            .set_instance_config(
                "password_login",
                Some(if form.password_login.is_some() {
                    "on"
                } else {
                    "off"
                }),
            )
            .await?;
        let caches_public = form.caches_public.is_some();
        deps.db
            .set_instance_config(
                "caches_public",
                Some(if caches_public { "on" } else { "off" }),
            )
            .await?;
        // Refresh the live masthead/gating flag so the change takes effect for
        // this serving process without a restart.
        crate::web::console_render::set_caches_public(caches_public);
        deps.db
            .set_instance_config("session_lifetime_secs", Some(&form.session_lifetime_secs))
            .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(err) = result {
        return internal(err);
    }
    audit_instance(&deps, &session, "instance.signup_policy", policy.as_str()).await;
    render_instance(
        &deps,
        &session,
        "general",
        Some("Signup &amp; identity saved."),
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
    let result = async {
        for (key, value) in [
            ("site_title", &form.site_title),
            ("tagline", &form.tagline),
            ("announcement", &form.announcement),
            ("tos_url", &form.tos_url),
            ("privacy_url", &form.privacy_url),
            ("support_url", &form.support_url),
        ] {
            deps.db.set_instance_config(key, Some(value)).await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(err) = result {
        return internal(err);
    }
    // Refresh the process chrome so the new title/banner/footer take effect for
    // this shell immediately (other Worker isolates pick it up as they recycle).
    crate::web::console_render::set_site_chrome(
        opt(&form.site_title),
        opt(&form.tagline),
        opt(&form.announcement),
        opt(&form.tos_url),
        opt(&form.privacy_url),
        opt(&form.support_url),
    );
    audit_instance(&deps, &session, "instance.branding", &form.site_title).await;
    render_instance(
        &deps,
        &session,
        "branding",
        Some("Branding saved."),
        started,
    )
    .await
}

/// `POST /-/instance/serving` form: default crawl policy and max upload size.
#[derive(serde::Deserialize)]
pub(crate) struct InstanceServingForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    default_crawl_policy: String,
    #[serde(default)]
    max_upload_bytes: String,
}

/// `POST /-/instance/serving` — update serving defaults (instance admins).
pub(crate) async fn instance_serving_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<InstanceServingForm>,
) -> Response {
    let session = match require_instance_admin(&deps, &headers, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // Validate the crawl policy through the same parser the registry uses.
    let policy = crate::crawl::CrawlPolicy::parse_or_default(&form.default_crawl_policy);
    let result = async {
        deps.db
            .set_instance_config("default_crawl_policy", Some(policy.as_str()))
            .await?;
        deps.db
            .set_instance_config("max_upload_bytes", Some(&form.max_upload_bytes))
            .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(err) = result {
        return internal(err);
    }
    audit_instance(&deps, &session, "instance.serving", policy.as_str()).await;
    render_instance(
        &deps,
        &session,
        "serving",
        Some("Serving defaults saved."),
        started,
    )
    .await
}

/// `POST /-/instance/storage` — manage the instance default storage binding's
/// public access and frontends (instance admins; RFC-0004 §12). Dispatches the
/// `op` field: `set-public` (access + `endpoint`), `add-frontend`,
/// `delete-frontend`.
pub(crate) async fn instance_storage_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let field = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
    let session = match require_instance_admin(&deps, &headers, field("csrf")).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let binding = match deps.db.instance_default_binding().await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return (StatusCode::CONFLICT, "instance default binding not seeded").into_response()
        }
        Err(err) => return internal(err),
    };
    let op = field("op").to_string();
    let outcome: Result<&str, String> = match op.as_str() {
        "set-public" => {
            let url = field("endpoint").trim();
            let url = (!url.is_empty()).then_some(url);
            deps.db
                .set_binding_public(binding.id, field("access"), url)
                .await
                .map(|_| "Public access saved.")
                .map_err(|e| format!("{e:#}"))
        }
        "add-frontend" => {
            let priority: i64 = field("consumer_priority").trim().parse().unwrap_or(100);
            deps.db
                .create_storage_frontend(
                    binding.id,
                    field("domain").trim(),
                    field("base_path").trim(),
                    if field("mode") == "proxied" {
                        "proxied"
                    } else {
                        "direct"
                    },
                    field("serves_git") == "1",
                    field("serves_cache") == "1",
                    field("serves_web") == "1",
                    priority,
                    field("advertised") == "1",
                )
                .await
                .map(|_| "Frontend added.")
                .map_err(|e| format!("{e:#}"))
        }
        "edit-frontend" => {
            let Ok(id) = field("id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad frontend id").into_response();
            };
            // Only a frontend belonging to this binding may be edited here.
            match deps.db.list_storage_frontends(binding.id).await {
                Ok(list) if list.iter().any(|f| f.id == id) => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such frontend").into_response(),
                Err(err) => return internal(err),
            }
            let priority: i64 = field("consumer_priority").trim().parse().unwrap_or(100);
            deps.db
                .update_frontend(
                    id,
                    field("domain").trim(),
                    field("base_path").trim(),
                    if field("mode") == "proxied" {
                        "proxied"
                    } else {
                        "direct"
                    },
                    field("serves_git") == "1",
                    field("serves_cache") == "1",
                    field("serves_web") == "1",
                    priority,
                    field("advertised") == "1",
                )
                .await
                .map(|_| "Frontend updated.")
                .map_err(|e| format!("{e:#}"))
        }
        "delete-frontend" => {
            let Ok(id) = field("id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad frontend id").into_response();
            };
            // Only a frontend belonging to this binding may be deleted here.
            match deps.db.list_storage_frontends(binding.id).await {
                Ok(list) if list.iter().any(|f| f.id == id) => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such frontend").into_response(),
                Err(err) => return internal(err),
            }
            deps.db
                .delete_frontend(id)
                .await
                .map(|_| "Frontend deleted.")
                .map_err(|e| format!("{e:#}"))
        }
        _ => return (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    };
    let notice = match outcome {
        Ok(notice) => notice,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    audit_instance(&deps, &session, "instance.storage", &op).await;
    render_instance(&deps, &session, "storage", Some(notice), started).await
}

/// Trim a form field to `Option`, mapping blank to `None`.
fn opt(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// Best-effort audit row for an instance-settings mutation (non-fatal).
async fn audit_instance(deps: &ConsoleDeps, session: &Session, action: &str, detail: &str) {
    if let Err(err) = deps
        .db
        .record_audit(
            "user",
            Some(session.auth.user_id),
            &session.email,
            action,
            "",
            None,
            None,
            None,
            Some(detail),
        )
        .await
    {
        tracing::warn!(error = %format!("{err:#}"), "recording {action} audit");
    }
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

/// Returns the committed `[caches]` priority for `url`, matching by URL with
/// trailing slashes normalized so a frontend `https://c/` matches a committed
/// `https://c`.
fn committed_priority(
    committed: &std::collections::BTreeMap<String, u32>,
    url: &str,
) -> Option<u32> {
    let target = url.trim_end_matches('/');
    committed
        .iter()
        .find(|(committed_url, _)| committed_url.trim_end_matches('/') == target)
        .map(|(_, priority)| *priority)
}

/// Removes the committed-URL entry matching `url` (trailing-slash-normalized),
/// so what remains is the set of committed URLs with no managed-cache match.
fn remove_matching_url(committed: &mut std::collections::BTreeMap<String, u32>, url: &str) {
    let target = url.trim_end_matches('/').to_string();
    let key = committed
        .keys()
        .find(|committed_url| committed_url.trim_end_matches('/') == target)
        .cloned();
    if let Some(key) = key {
        committed.remove(&key);
    }
}

/// Render one registry settings section (`general` / `storage` / `caches` /
/// `danger`) — the split of the former single dense settings page. All load the
/// same data and differ only in which section `registry_settings_page` renders.
async fn registry_settings_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<&str>,
    active: &str,
    started: Instant,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) = require_org_perm(deps, session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let result_outcome = async {
        let binding = match registry.storage_binding_id {
            Some(id) => deps
                .db
                .storage_binding(id)
                .await?
                .map(|b| (b.name, b.root, registry.prefix.clone())),
            None => None,
        };
        // Resolve the owning org slug (for cache links) and the binary caches
        // that serve this registry — the reverse of a cache's linked registries.
        let org_slug = match registry.org_id {
            Some(id) => deps
                .db
                .org_by_id(id)
                .await?
                .map(|o| o.slug)
                .unwrap_or_default(),
            None => String::new(),
        };
        // The committed `[caches]` the indexer flattened — the single source of
        // truth a consumer resolves. The reconciliation view below classifies
        // each managed cache against this list by its consumer URL.
        let committed = deps.db.list_advertised_caches(registry.id).await?;
        let mut committed_unmatched: std::collections::BTreeMap<String, u32> =
            committed.iter().map(|(u, p)| (u.clone(), *p)).collect();

        let mut caches = Vec::new();
        let mut linked_ids = std::collections::HashSet::new();
        for link in deps.db.cache_links_for_registry(registry.id).await? {
            linked_ids.insert(link.cache_id);
            if let Some(cache) = deps.db.cache_by_id(link.cache_id).await? {
                if cache.deleted_at.is_none() {
                    let url =
                        crate::service::cache_consumer_url(&deps.db, &deps.external_url, &cache)
                            .await?;
                    // Served-from-config when the cache's consumer URL appears
                    // in the committed `[caches]` (compared trim-trailing-slash).
                    let served = committed_priority(&committed_unmatched, &url);
                    if served.is_some() {
                        remove_matching_url(&mut committed_unmatched, &url);
                    }
                    caches.push(console::RegistryCacheRow {
                        cache_slug: cache.slug,
                        consumer_url: url,
                        roots_packages: link.roots_packages,
                        config_priority: served,
                    });
                }
            }
        }
        // What is left in the committed list matches no linked managed cache:
        // third-party or non-hosted URLs the registry advertises directly.
        let mut external_caches: Vec<(String, u32)> = committed_unmatched.into_iter().collect();
        external_caches.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        // Caches in this registry's org that aren't linked yet — the options for
        // the "link a cache" control on the settings page.
        let mut linkable_caches = Vec::new();
        for c in deps.db.list_caches().await? {
            if c.org_id == registry.org_id && c.deleted_at.is_none() && !linked_ids.contains(&c.id)
            {
                linkable_caches.push((c.slug, c.visibility));
            }
        }
        // The org's storage bindings — targets for the "change storage" control.
        let binding_names: Vec<String> = match registry.org_id {
            Some(org_id) => deps
                .db
                .list_storage_bindings(org_id)
                .await?
                .into_iter()
                .map(|b| b.name)
                .collect(),
            None => Vec::new(),
        };
        let can_delete = session.allows(&deps.db, Permission::IamAdmin, &scope).await;
        let advertise_frontend = deps
            .db
            .registry_advertises_storage_frontend(registry.id)
            .await?;
        let binding_ref = binding
            .as_ref()
            .map(|(n, r, p)| (n.as_str(), r.as_str(), p.as_str()));
        let placements =
            placement_overview_rows(deps, crate::db::SurfaceTarget::Registry(registry.id)).await?;
        Ok::<_, anyhow::Error>(console::registry_settings_page(
            &session.email,
            registry,
            &org_slug,
            &session.csrf(),
            binding_ref,
            &placements,
            &binding_names,
            &caches,
            &external_caches,
            &linkable_caches,
            can_delete,
            advertise_frontend,
            result,
            active,
            started,
        ))
    }
    .await;
    match result_outcome {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

/// `GET /{slug}/-/settings/general` — registry visibility and crawl policy.
pub(crate) async fn registry_general(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "general").await
}

/// `GET /{slug}/-/settings/storage` — the registry's storage tab.
pub(crate) async fn registry_storage(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "storage").await
}

/// `GET /{slug}/-/settings/caches` — the registry's binary-caches tab.
pub(crate) async fn registry_caches(
    deps: ConsoleDeps,
    headers: HeaderMap,
    started: RequestStart,
    uri: axum::http::Uri,
    path: Path<String>,
) -> Response {
    registry_settings_section(deps, headers, started, uri, path, "caches").await
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

/// `POST /{slug}/-/settings/cache-link` form: the cache and the link flags.
#[derive(serde::Deserialize)]
pub(crate) struct RegistryCacheLinkForm {
    #[serde(default)]
    csrf: String,
    cache: String,
    #[serde(default)]
    advertised: Option<String>,
    #[serde(default)]
    roots_packages: Option<String>,
}

/// `POST /{slug}/-/settings/cache-link` — link a cache to this registry, or
/// update an existing link's flags, from the registry side.
///
/// `link_cache` is an upsert, so this both creates a new link and edits an
/// existing one's `advertised`/`roots_packages` flags. The cross-visibility
/// policy is enforced through the shared [`assess_cache_link`] chokepoint, the
/// same as the cache-side route and the RPC. A link is an operational
/// association only; advertising the cache to consumers is an explicit edit of
/// the registry's committed `[[caches]]` config (Settings -> Config), never a
/// write-through from linking.
pub(crate) async fn registry_cache_link(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<RegistryCacheLinkForm>,
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
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let advertised = form.advertised.is_some();
    let roots_packages = form.roots_packages.is_some();
    let outcome = async {
        let Some(cache) = deps.db.cache_by_slug(form.cache.trim()).await? else {
            return Ok(Err("unknown cache".to_string()));
        };
        if cache.org_id != registry.org_id {
            return Ok(Err("cache is not in this organization".to_string()));
        }
        let advisory = crate::service::assess_cache_link(
            &cache.slug,
            &cache.visibility,
            &registry.slug,
            &registry.visibility,
            advertised,
            roots_packages,
        );
        if let Some(reject) = advisory.reject {
            return Ok(Err(reject));
        }
        deps.db
            .link_cache(cache.id, registry.id, roots_packages, advertised)
            .await?;
        // A link is an operational association only (GC-root pinning + the
        // config-editor autofill source); it never writes the registry's
        // committed `registry.toml`. Advertising a cache to consumers is an
        // explicit edit of the `[caches]` config — see Settings -> Config.
        Ok::<Result<String, String>, anyhow::Error>(Ok("Cache link saved.".to_string()))
    }
    .await;
    match outcome {
        Ok(Ok(notice)) => {
            registry_settings_view(&deps, &session, &registry, Some(&notice), "caches", started)
                .await
        }
        Ok(Err(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /{slug}/-/settings/cache-unlink` form: the cache to unlink.
#[derive(serde::Deserialize)]
pub(crate) struct RegistryCacheUnlinkForm {
    #[serde(default)]
    csrf: String,
    cache: String,
}

/// `POST /{slug}/-/settings/cache-unlink` — remove a cache⇄registry link from
/// the registry side.
pub(crate) async fn registry_cache_unlink(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<RegistryCacheUnlinkForm>,
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
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let outcome = async {
        let notice = "Cache unlinked.".to_string();
        if let Some(cache) = deps.db.cache_by_slug(form.cache.trim()).await? {
            deps.db.unlink_cache(cache.id, registry.id).await?;
            // Unlinking only drops the operational association; the committed
            // `[[caches]]` config is edited explicitly via Settings -> Config.
        }
        Ok::<String, anyhow::Error>(notice)
    }
    .await;
    match outcome {
        Ok(notice) => {
            registry_settings_view(&deps, &session, &registry, Some(&notice), "caches", started)
                .await
        }
        Err(err) => internal(err),
    }
}

/// `POST /{slug}/-/settings/storage` form: the target binding (empty = default).
#[derive(serde::Deserialize)]
pub(crate) struct ChangeStorageForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    binding: String,
}

/// `POST /{slug}/-/settings/storage` — migrate a registry's surface to a
/// different storage backend.
///
/// Resolves the target binding (an empty value = the deployment default), then
/// copies every object to it and re-points the registry via
/// [`migrate_registry_storage`](crate::migrate::migrate_registry_storage). A
/// no-op move or a backend that can't enumerate surfaces back as a `400` with
/// the reason.
pub(crate) async fn registry_change_storage(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<ChangeStorageForm>,
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
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let result = async {
        let new_binding_id =
            match resolve_target_binding(&deps, registry.org_id, &form.binding).await? {
                Ok(id) => id,
                Err(msg) => return Ok(Some(msg)),
            };
        match crate::migrate::migrate_registry_storage(
            &deps.db,
            deps.surface.as_ref(),
            deps.surface_write.as_ref(),
            deps.reindexer.as_ref(),
            &registry,
            new_binding_id,
        )
        .await
        {
            Ok(_) => Ok(None),
            Err(err) => Ok(Some(format!("{err:#}"))),
        }
    }
    .await;
    match result {
        Ok(None) => {
            registry_settings_view(&deps, &session, &registry, None, "storage", started).await
        }
        Ok(Some(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /{slug}/-/settings/advertise-frontend` form: the advertise checkbox.
#[derive(serde::Deserialize)]
pub(crate) struct AdvertiseFrontendForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    advertise: Option<String>,
}

/// `POST /{slug}/-/settings/advertise-frontend` — toggle whether the registry
/// advertises its inherited storage-binding frontend (RFC-0004 §12).
pub(crate) async fn registry_set_advertise_frontend(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<AdvertiseFrontendForm>,
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
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) =
        require_org_perm(&deps, &session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    if let Err(err) = deps
        .db
        .set_registry_advertise_storage_frontend(registry.id, form.advertise.is_some())
        .await
    {
        return internal(err);
    }
    serving_view(
        &deps,
        &session,
        &registry,
        Some("Serving route updated."),
        started,
    )
    .await
}

/// Resolve a storage-change form's `binding` value to a target binding id.
///
/// An empty value means the deployment default (`Ok(Ok(None))`). A named
/// binding is looked up in the org; an unknown name or an org-less registry
/// returns a user-facing message (`Ok(Err(msg))`).
async fn resolve_target_binding(
    deps: &ConsoleDeps,
    org_id: Option<i64>,
    binding: &str,
) -> anyhow::Result<Result<Option<i64>, String>> {
    let name = binding.trim();
    if name.is_empty() {
        return Ok(Ok(None));
    }
    let Some(org_id) = org_id else {
        return Ok(Err("registry has no organization".to_string()));
    };
    let found = deps
        .db
        .list_storage_bindings(org_id)
        .await?
        .into_iter()
        .find(|b| b.name == name);
    match found {
        Some(b) => Ok(Ok(Some(b.id))),
        None => Ok(Err("unknown storage binding".to_string())),
    }
}

/// `POST /{slug}/-/settings/visibility` form: the new visibility.
#[derive(serde::Deserialize)]
pub(crate) struct VisibilityForm {
    #[serde(default)]
    csrf: String,
    visibility: String,
}

/// `POST /{slug}/-/settings/visibility` — change a registry's visibility.
pub(crate) async fn registry_visibility(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<VisibilityForm>,
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
    registry_visibility_action(
        &deps,
        &session,
        &registry,
        &form.csrf,
        &form.visibility,
        started,
    )
    .await
}

/// The visibility-change action.
async fn registry_visibility_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    visibility: &str,
    started: Instant,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) = require_org_perm(deps, session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let visibility = match visibility.trim() {
        v @ ("public" | "internal" | "private") => v,
        _ => return (StatusCode::BAD_REQUEST, "invalid visibility").into_response(),
    };
    let change_id = match config::change_registry_visibility(
        &deps.db,
        &session.principal(),
        &session.email,
        registry.id,
        visibility,
    )
    .await
    {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    let updated = match deps.db.registry_by_slug(&registry.slug).await {
        Ok(Some(reg)) => reg,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    registry_settings_view(
        deps,
        session,
        &updated,
        Some(change_id.0.as_str()),
        "general",
        started,
    )
    .await
}

/// `POST /{slug}/-/settings/crawl` form: the new crawl policy.
#[derive(serde::Deserialize)]
pub(crate) struct CrawlPolicyForm {
    #[serde(default)]
    csrf: String,
    policy: String,
}

/// `POST /{slug}/-/settings/crawl` — change a registry's crawl policy.
pub(crate) async fn registry_crawl_policy(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<CrawlPolicyForm>,
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
    registry_crawl_policy_action(
        &deps,
        &session,
        &registry,
        &form.csrf,
        &form.policy,
        started,
    )
    .await
}

/// The crawl-policy-change action (mirrors [`registry_visibility_action`]).
async fn registry_crawl_policy_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    policy: &str,
    started: Instant,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) = require_org_perm(deps, session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let policy = match crate::crawl::CrawlPolicy::parse(policy.trim()) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid crawl policy").into_response(),
    };
    let change_id = match config::change_registry_crawl_policy(
        &deps.db,
        &session.principal(),
        &session.email,
        registry.id,
        policy.as_str(),
    )
    .await
    {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    let updated = match deps.db.registry_by_slug(&registry.slug).await {
        Ok(Some(reg)) => reg,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    registry_settings_view(
        deps,
        session,
        &updated,
        Some(change_id.0.as_str()),
        "general",
        started,
    )
    .await
}

/// `POST /{slug}/-/settings/delete` form: the typed-confirmation name.
#[derive(serde::Deserialize)]
pub(crate) struct RegistryDeleteForm {
    #[serde(default)]
    csrf: String,
    confirm: String,
}

/// `POST /{slug}/-/settings/delete` — unregister a registry.
pub(crate) async fn registry_delete(
    deps: ConsoleDeps,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<RegistryDeleteForm>,
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
    registry_delete_action(
        &deps,
        &session,
        &registry,
        &form.csrf,
        &form.confirm,
        &headers,
    )
    .await
}

/// The registry-delete action.
async fn registry_delete_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    confirm: &str,
    headers: &HeaderMap,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(session, headers) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) = require_org_perm(deps, session, &scope, Permission::IamAdmin).await {
        return *deny;
    }
    if confirm.trim() != registry.slug {
        return (StatusCode::BAD_REQUEST, "type the registry name to confirm").into_response();
    }
    let result = async {
        let removed = deps.db.delete_registry(registry.id).await?;
        if removed {
            deps.db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "registry.delete",
                    &registry.slug,
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
        }
        let target = match registry.org_id {
            Some(org_id) => match deps.db.org_by_id(org_id).await? {
                Some(org) => registry_delete_target(Some(&org.slug)),
                None => registry_delete_target(None),
            },
            None => registry_delete_target(None),
        };
        Ok::<_, anyhow::Error>(target)
    }
    .await;
    match result {
        Ok(target) => Redirect::to(&target).into_response(),
        Err(err) => internal(err),
    }
}

/// Returns the post-delete inventory destination for a registry.
fn registry_delete_target(org_slug: Option<&str>) -> String {
    org_slug.map_or_else(
        || "/".to_string(),
        |slug| format!("/-/org/{slug}/registries"),
    )
}

// -- registry tokens --------------------------------------------------------

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
    headers: &HeaderMap,
    page_number: usize,
    started: Instant,
) -> Response {
    if let Err(deny) = authorize_registry_read(deps, registry, headers).await {
        return *deny;
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
    started: Instant,
    headers: &HeaderMap,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(session, headers) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&deps.db, Permission::TokensSelf, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "tokens.self required").into_response();
    }
    let mut perms = Vec::new();
    if want_read {
        perms.push(Permission::Read);
    }
    if want_publish {
        perms.push(Permission::Publish);
    }
    let grants = match session.grants(&deps.db).await {
        Ok(grants) => grants,
        Err(err) => return internal(err),
    };
    perms.retain(|p| iam::allow(&grants, *p, &scope));
    let (_, secret) = match deps
        .db
        .create_token(
            session.principal(),
            scope.as_str(),
            &perms,
            Some("created via console"),
            None,
        )
        .await
    {
        Ok(pair) => pair,
        Err(err) => return internal(err),
    };
    render_tokens(
        deps,
        session,
        registry,
        Some(("New token created", &secret)),
        1,
        started,
    )
    .await
}

/// The token revoke/rotate action: CSRF + ownership gate, then mutate.
async fn tokens_modify_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    token_id: &str,
    rotate: bool,
    started: Instant,
    headers: &HeaderMap,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = ensure_owns_token(deps, session, token_id).await {
        return *resp;
    }
    if rotate {
        if let Err(resp) = require_sudo(session, headers) {
            return *resp;
        }
        match deps.db.rotate_token(token_id).await {
            Ok(Some((_, secret))) => {
                // RFC-0004 ch.14 Phase C: tombstone the old token id so any
                // KV-cached resolution for it is rejected immediately.
                deps.invalidate_token_cache(token_id).await;
                render_tokens(
                    deps,
                    session,
                    registry,
                    Some(("Token rotated", &secret)),
                    1,
                    started,
                )
                .await
            }
            Ok(None) => {
                Redirect::to(&format!("/{}/-/settings/tokens", registry.slug)).into_response()
            }
            Err(err) => internal(err),
        }
    } else {
        match deps.db.revoke_token(token_id).await {
            Ok(()) => {
                // RFC-0004 ch.14 Phase C: tombstone the revoked token id.
                deps.invalidate_token_cache(token_id).await;
                Redirect::to(&format!("/{}/-/settings/tokens", registry.slug)).into_response()
            }
            Err(err) => internal(err),
        }
    }
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
    let scope = Scope::parse(&registry.slug);
    let can_create = session
        .allows(&deps.db, Permission::TokensSelf, &scope)
        .await;
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
        started,
        &headers,
    )
    .await
}

/// `POST` token revoke/rotate form: the target token id.
#[derive(serde::Deserialize)]
pub(crate) struct TokenIdForm {
    #[serde(default)]
    csrf: String,
    token_id: String,
}

/// `POST /{slug}/-/settings/tokens/revoke` — revoke one of the caller's tokens.
pub(crate) async fn tokens_revoke(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
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
        &form.token_id,
        false,
        started,
        &headers,
    )
    .await
}

/// `POST /{slug}/-/settings/tokens/rotate` — rotate one of the caller's tokens.
pub(crate) async fn tokens_rotate(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
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
        &form.token_id,
        true,
        started,
        &headers,
    )
    .await
}

/// Verify the session user owns the token being revoked/rotated, else 403.
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

/// `GET /{slug}/-/channels/{name}/console` — the rollout console.
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
    if let Err(deny) = authorize_registry_read(&deps, &registry, &headers).await {
        return *deny;
    }
    render_channel_console(&deps, &session, &registry, &name, None, None, started).await
}

/// Render the channel console.
async fn render_channel_console(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    name: &str,
    prepared: Option<(&str, &str)>,
    advanced: Option<&str>,
    started: Instant,
) -> Response {
    let result = async {
        let status = deps.db.index_status(registry.id).await?;
        let channels = deps.db.list_channels(registry.id).await?;
        let Some(channel) = channels.into_iter().find(|c| c.name == name) else {
            return Ok(None);
        };
        let scope = Scope::parse(&registry.slug);
        let can_advance = session
            .allows(&deps.db, Permission::ChannelAdvance, &scope)
            .await;
        let hosted_key = match registry.hosted_key_id {
            Some(id) => deps.db.hosted_key(id).await?.map(|k| k.key_id),
            None => None,
        };
        Ok::<_, anyhow::Error>(Some(console::channel_console(
            &session.email,
            registry,
            status.as_ref(),
            &channel,
            &session.csrf(),
            can_advance,
            hosted_key.as_deref(),
            prepared,
            advanced,
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

/// `POST /{slug}/-/channels/{name}/console` form: the advance request.
#[derive(serde::Deserialize)]
pub(crate) struct AdvanceForm {
    #[serde(default)]
    csrf: String,
    release: String,
    partitions: Option<String>,
}

/// `POST /{slug}/-/channels/{name}/console` — prepare a channel advance.
pub(crate) async fn channel_advance(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<AdvanceForm>,
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
    channel_advance_action(
        &deps,
        &session,
        &registry,
        &name,
        &form.csrf,
        &form.release,
        form.partitions.as_deref(),
        started,
    )
    .await
}

/// The channel-advance action: record a prepared operation and render its `apr`
/// command.
async fn channel_advance_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    name: &str,
    csrf: &str,
    release: &str,
    partitions: Option<&str>,
    started: Instant,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&deps.db, Permission::ChannelAdvance, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "channel.advance required").into_response();
    }
    let release = release.trim();
    if release.is_empty() {
        return (StatusCode::BAD_REQUEST, "release is required").into_response();
    }
    let partitions: u16 = partitions
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(256)
        .clamp(1, 256);
    let change_id = match config::prepare_channel_advance(
        &deps.db,
        &session.principal(),
        &session.email,
        &registry.slug,
        name,
        release,
        partitions,
    )
    .await
    {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    let registry_url = format!(
        "{}/{}",
        deps.external_url.trim_end_matches('/'),
        registry.slug
    );
    let command = config::advance_command(&registry_url, &change_id);
    render_channel_console(
        deps,
        session,
        registry,
        name,
        Some((change_id.as_str(), &command)),
        None,
        started,
    )
    .await
}

/// `POST /{slug}/-/channels/{name}/advance` — directly advance a hosted-key
/// channel.
pub(crate) async fn channel_advance_direct(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<AdvanceForm>,
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
    advance_direct_action(
        &deps,
        &session,
        &registry,
        &name,
        &form.csrf,
        &form.release,
        form.partitions.as_deref(),
        started,
    )
    .await
}

/// The direct hosted-key advance action: sign and apply the advance through the
/// shared [`advance_channel`](crate::signing::advance_channel) over the
/// console's surface-write and reindex ports (or fall back to a prepared
/// operation when no hosted key is bound).
async fn advance_direct_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    name: &str,
    csrf: &str,
    release: &str,
    partitions: Option<&str>,
    started: Instant,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&deps.db, Permission::ChannelAdvance, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "channel.advance required").into_response();
    }
    if registry.hosted_key_id.is_none() {
        return channel_advance_action(
            deps, session, registry, name, csrf, release, partitions, started,
        )
        .await;
    }
    let release = release.trim();
    if release.is_empty() {
        return (StatusCode::BAD_REQUEST, "release is required").into_response();
    }
    let count: usize = partitions
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(256usize)
        .clamp(1, 256);
    let when = crate::clock::now_unix_secs();
    let result = crate::signing::advance_channel(
        &deps.db,
        deps.sealer.as_ref(),
        deps.surface_write.as_ref(),
        deps.reindexer.as_ref(),
        registry,
        name,
        release,
        count,
        when,
    )
    .await;
    match result {
        Ok(outcome) => {
            let message = format!(
                "Advanced {} to {} · {} partition(s) moved · {}% rolled out",
                outcome.channel, outcome.release, outcome.moved, outcome.rollout_percent,
            );
            render_channel_console(deps, session, registry, name, None, Some(&message), started)
                .await
        }
        Err(err) => (StatusCode::BAD_REQUEST, format!("advance failed: {err:#}")).into_response(),
    }
}

// -- hosted signing keys ----------------------------------------------------

/// `GET /-/org/{org}/keys` — the org hosted-key enrollment page.
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

/// Render the org hosted-keys page.
async fn render_org_keys(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    created: Option<&str>,
    started: Instant,
) -> Response {
    let scope = Scope::parse(org_slug);
    if !session
        .allows(&deps.db, Permission::KeysManage, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "keys.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(org_slug).await? else {
            return Ok(None);
        };
        let keys = deps.db.list_hosted_keys(org.id).await?;
        let registries: Vec<RegistryRecord> = deps
            .db
            .list_registries()
            .await?
            .into_iter()
            .filter(|r| r.org_id == Some(org.id))
            .collect();
        Ok::<_, anyhow::Error>(Some(console::org_hosted_keys_page(
            &session.email,
            &org,
            &session.csrf(),
            &keys,
            &registries,
            created,
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

/// `POST /-/org/{org}/keys` form: enroll a key or attach one to a registry.
#[derive(serde::Deserialize)]
pub(crate) struct OrgKeysForm {
    #[serde(default)]
    csrf: String,
    op: String,
    #[serde(default)]
    key_id: String,
    #[serde(default)]
    registry: String,
    #[serde(default)]
    hosted_key_id: String,
}

/// `POST /-/org/{org}/keys` — enroll or attach a hosted signing key.
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
    let scope = Scope::parse(&org_slug);
    if !session
        .allows(&deps.db, Permission::KeysManage, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "keys.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(org) = (match deps.db.org_by_slug(&org_slug).await {
        Ok(org) => org,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match form.op.as_str() {
        "create" => {
            let key_id = form.key_id.trim();
            if key_id.is_empty() {
                return (StatusCode::BAD_REQUEST, "key id is required").into_response();
            }
            let public = match deps
                .db
                .create_hosted_key(deps.sealer.as_ref(), org.id, key_id)
                .await
            {
                Ok(line) => line,
                Err(err) => {
                    return (StatusCode::BAD_REQUEST, format!("enroll failed: {err:#}"))
                        .into_response()
                }
            };
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "hosted_key.create",
                    &org_slug,
                    None,
                    None,
                    None,
                    Some(key_id),
                )
                .await
            {
                return internal(err);
            }
            render_org_keys(&deps, &session, &org_slug, Some(&public), started).await
        }
        "attach" => {
            let Some(registry) = (match deps.db.registry_by_slug(form.registry.trim()).await {
                Ok(reg) => reg,
                Err(err) => return internal(err),
            }) else {
                return (StatusCode::BAD_REQUEST, "no such registry").into_response();
            };
            if registry.org_id != Some(org.id) {
                return (StatusCode::FORBIDDEN, "registry not in this org").into_response();
            }
            let hosted_key_id: Option<i64> = match form.hosted_key_id.trim() {
                "" => None,
                raw => match raw.parse() {
                    Ok(id) => Some(id),
                    Err(_) => {
                        return (StatusCode::BAD_REQUEST, "bad hosted key id").into_response()
                    }
                },
            };
            if let Some(id) = hosted_key_id {
                match deps.db.hosted_key(id).await {
                    Ok(Some(k)) if k.org_id == org.id => {}
                    Ok(_) => {
                        return (StatusCode::BAD_REQUEST, "no such hosted key in this org")
                            .into_response()
                    }
                    Err(err) => return internal(err),
                }
            }
            if let Err(err) = deps
                .db
                .set_registry_hosted_key(registry.id, hosted_key_id)
                .await
            {
                return internal(err);
            }
            let detail = serde_json::json!({ "hosted_key_id": hosted_key_id }).to_string();
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "hosted_key.attach",
                    &registry.slug,
                    None,
                    None,
                    None,
                    Some(&detail),
                )
                .await
            {
                return internal(err);
            }
            render_org_keys(&deps, &session, &org_slug, None, started).await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
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
    render_org_webhooks(&deps, &session, &org_slug, None, started).await
}

/// Render the org webhooks page.
async fn render_org_webhooks(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    created_secret: Option<&str>,
    started: Instant,
) -> Response {
    let scope = Scope::parse(org_slug);
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "members.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
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
            created_secret,
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

/// `POST /-/org/{org}/webhooks` — create or delete a webhook subscription.
pub(crate) async fn org_webhooks_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let mut single: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut events: Vec<String> = Vec::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        if key == "events" {
            let value = value.trim().to_string();
            if !value.is_empty() {
                events.push(value);
            }
        } else {
            single.insert(key.into_owned(), value.into_owned());
        }
    }
    let field = |k: &str| single.get(k).map(String::as_str).unwrap_or("");

    if let Err(resp) = check_csrf(&session, field("csrf")) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session
        .allows(&deps.db, Permission::MembersManage, &scope)
        .await
    {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "members.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(org) = (match deps.db.org_by_slug(&org_slug).await {
        Ok(org) => org,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match field("op") {
        "create" => {
            let url = field("url").trim();
            if url.is_empty() {
                return (StatusCode::BAD_REQUEST, "url is required").into_response();
            }
            if let Err(err) = crate::url_guard::is_safe_remote_url(url) {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("rejecting webhook url: {err:#}"),
                )
                    .into_response();
            }
            let known: Vec<&str> = console::WEBHOOK_EVENT_TYPES
                .iter()
                .map(|(e, _)| *e)
                .collect();
            if let Some(bad) = events.iter().find(|e| !known.contains(&e.as_str())) {
                return (StatusCode::BAD_REQUEST, format!("unknown event: {bad}")).into_response();
            }
            let provided = field("secret").trim().to_string();
            let generated = provided.is_empty();
            let secret = if generated {
                crate::auth::token::generate_token().0
            } else {
                provided
            };
            let id = match deps.db.create_webhook(org.id, url, &secret, &events).await {
                Ok(id) => id,
                Err(err) => return internal(err),
            };
            let detail = serde_json::json!({ "id": id, "url": url, "events": events }).to_string();
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "webhook.create",
                    &org_slug,
                    None,
                    None,
                    None,
                    Some(&detail),
                )
                .await
            {
                return internal(err);
            }
            render_org_webhooks(
                &deps,
                &session,
                &org_slug,
                generated.then_some(secret.as_str()),
                started,
            )
            .await
        }
        "delete" => {
            let Ok(webhook_id) = field("webhook_id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad webhook id").into_response();
            };
            match deps.db.webhook(webhook_id).await {
                Ok(Some(w)) if w.org_id == org.id => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such webhook").into_response(),
                Err(err) => return internal(err),
            }
            if let Err(err) = deps.db.delete_webhook(webhook_id).await {
                return internal(err);
            }
            let detail = serde_json::json!({ "id": webhook_id }).to_string();
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "webhook.delete",
                    &org_slug,
                    None,
                    None,
                    None,
                    Some(&detail),
                )
                .await
            {
                return internal(err);
            }
            render_org_webhooks(&deps, &session, &org_slug, None, started).await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
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

/// Whether `session` may verify captured domains: an *instance* admin only.
async fn can_verify_domains(deps: &ConsoleDeps, session: &Session) -> bool {
    session
        .allows(&deps.db, Permission::IamAdmin, &Scope::parse(""))
        .await
}

/// Render the org SSO page.
async fn render_org_sso(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    let scope = Scope::parse(org_slug);
    if !session.allows(&deps.db, Permission::IamAdmin, &scope).await {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "iam.admin required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(org_slug).await? else {
            return Ok(None);
        };
        let idp = deps.db.idp_config(org.id).await?;
        let domains = deps.db.list_org_domains(org.id).await?;
        Ok::<_, anyhow::Error>(Some(console::org_sso_page(
            &session.email,
            &org,
            &session.csrf(),
            idp.as_ref(),
            &domains,
            can_verify_domains(deps, session).await,
            notice,
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

/// `POST /-/org/{org}/sso` — configure the IdP or manage captured domains.
pub(crate) async fn org_sso_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    Path(org_slug): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let fields = parse_form(&String::from_utf8_lossy(&body));
    let field = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");

    if let Err(resp) = check_csrf(&session, field("csrf")) {
        return *resp;
    }
    if let Err(resp) = require_sudo(&session, &headers) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session.allows(&deps.db, Permission::IamAdmin, &scope).await {
        if session.allows(&deps.db, Permission::Read, &scope).await {
            return (StatusCode::FORBIDDEN, "iam.admin required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(org) = (match deps.db.org_by_slug(&org_slug).await {
        Ok(org) => org,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match field("op") {
        "set-idp" => {
            let role_map = field("role_map").trim();
            let role_map = if role_map.is_empty() { "{}" } else { role_map };
            if serde_json::from_str::<serde_json::Value>(role_map).is_err() {
                return (StatusCode::BAD_REQUEST, "role map must be JSON").into_response();
            }
            let default_role = field("default_role").trim();
            if crate::domain::Role::parse(default_role).is_none() {
                return (StatusCode::BAD_REQUEST, "invalid default role").into_response();
            }
            let existing = match deps.db.idp_config(org.id).await {
                Ok(cfg) => cfg,
                Err(err) => return internal(err),
            };
            let client_secret_enc = {
                let provided = field("client_secret");
                if provided.is_empty() {
                    existing.and_then(|c| c.client_secret_enc)
                } else {
                    match deps.sealer.seal(provided) {
                        Ok(sealed) => Some(sealed),
                        Err(err) => return internal(err),
                    }
                }
            };
            let groups_claim = match field("groups_claim").trim() {
                "" => None,
                g => Some(g.to_string()),
            };
            let config = crate::db::IdpConfigRecord {
                org_id: org.id,
                issuer: field("issuer").trim().to_string(),
                authorization_endpoint: field("auth_url").trim().to_string(),
                token_endpoint: field("token_url").trim().to_string(),
                jwks_uri: field("jwks_uri").trim().to_string(),
                client_id: field("client_id").trim().to_string(),
                client_secret_enc,
                scopes: match field("scopes").trim() {
                    "" => "openid email profile".to_string(),
                    s => s.to_string(),
                },
                groups_claim,
                role_map_json: role_map.to_string(),
                allow_jit: field("allow_jit") == "1",
                enforce_sso: field("enforce_sso") == "1",
                default_role: default_role.to_string(),
            };
            if config.issuer.is_empty() || config.client_id.is_empty() {
                return (StatusCode::BAD_REQUEST, "issuer and client id are required")
                    .into_response();
            }
            if let Err(err) = deps.db.upsert_idp_config(&config).await {
                return internal(err);
            }
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "idp.set",
                    &org_slug,
                    None,
                    None,
                    None,
                    Some(&config.issuer),
                )
                .await
            {
                return internal(err);
            }
            render_org_sso(
                &deps,
                &session,
                &org_slug,
                Some("Identity provider saved."),
                started,
            )
            .await
        }
        "remove-idp" => {
            if let Err(err) = deps.db.delete_idp_config(org.id).await {
                return internal(err);
            }
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "idp.remove",
                    &org_slug,
                    None,
                    None,
                    None,
                    None,
                )
                .await
            {
                return internal(err);
            }
            render_org_sso(
                &deps,
                &session,
                &org_slug,
                Some("Identity provider removed."),
                started,
            )
            .await
        }
        "add-domain" => {
            let domain = field("domain").trim().to_lowercase();
            if domain.is_empty() || !domain.contains('.') {
                return (StatusCode::BAD_REQUEST, "a valid domain is required").into_response();
            }
            match deps.db.org_domain(&domain).await {
                Ok(Some(existing)) if existing.org_id != org.id => {
                    return (
                        StatusCode::CONFLICT,
                        format!("{domain} is already claimed by another organization"),
                    )
                        .into_response();
                }
                Ok(_) => {}
                Err(err) => return internal(err),
            }
            let challenge = match deps.db.add_org_domain(org.id, &domain).await {
                Ok(c) => c,
                Err(err) => return internal(err),
            };
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "domain.capture",
                    &org_slug,
                    None,
                    None,
                    None,
                    Some(&domain),
                )
                .await
            {
                return internal(err);
            }
            render_org_sso(
                &deps,
                &session,
                &org_slug,
                Some(&format!(
                    "Captured {domain} (unverified). Publish this TXT record: {challenge}"
                )),
                started,
            )
            .await
        }
        "verify-domain" => {
            if !can_verify_domains(&deps, &session).await {
                return (
                    StatusCode::FORBIDDEN,
                    "domain verification is an instance-operator action",
                )
                    .into_response();
            }
            let domain = field("domain").trim().to_lowercase();
            match deps.db.org_domain(&domain).await {
                Ok(Some(d)) if d.org_id == org.id => {}
                Ok(_) => {
                    return (StatusCode::NOT_FOUND, "domain not claimed by this org")
                        .into_response()
                }
                Err(err) => return internal(err),
            }
            if let Err(err) = deps.db.verify_org_domain(&domain).await {
                return internal(err);
            }
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "domain.verify",
                    &org_slug,
                    None,
                    None,
                    None,
                    Some(&domain),
                )
                .await
            {
                return internal(err);
            }
            render_org_sso(
                &deps,
                &session,
                &org_slug,
                Some(&format!("Verified {domain}.")),
                started,
            )
            .await
        }
        "remove-domain" => {
            let domain = field("domain").trim().to_lowercase();
            if let Err(err) = deps.db.delete_org_domain(org.id, &domain).await {
                return internal(err);
            }
            if let Err(err) = deps
                .db
                .record_audit(
                    "user",
                    Some(session.auth.user_id),
                    &session.email,
                    "domain.remove",
                    &org_slug,
                    None,
                    None,
                    None,
                    Some(&domain),
                )
                .await
            {
                return internal(err);
            }
            render_org_sso(
                &deps,
                &session,
                &org_slug,
                Some(&format!("Removed {domain}.")),
                started,
            )
            .await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- serving frontends + mirror ---------------------------------------------

/// `GET /{slug}/-/settings/serving` — the serving & mirror management page.
pub(crate) async fn serving(
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
    serving_view(&deps, &session, &registry, None, started).await
}

/// Render the serving & mirror page.
async fn serving_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    notice: Option<&str>,
    started: Instant,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        if let Err(deny) = authorize_registry_read(deps, registry, &HeaderMap::new()).await {
            return *deny;
        }
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let result = async {
        let frontends = deps.db.list_frontends(registry.id).await?;
        let mirror = deps.db.mirror_source(registry.id).await?;
        let advertise_storage_frontend = deps
            .db
            .registry_advertises_storage_frontend(registry.id)
            .await?;
        // Frontends inherited from the storage binding this registry lives on
        // (the instance-default binding when the registry is unbound): they also
        // serve this registry, under its prefix. Shown read-only, with a link to
        // edit them at the binding.
        let binding = match registry.storage_binding_id {
            Some(id) => deps.db.storage_binding(id).await?,
            None => deps.db.instance_default_binding().await?,
        };
        let (inherited, inh_label, inh_href) = match &binding {
            Some(b) => {
                let list = deps.db.list_storage_frontends(b.id).await?;
                let (label, href) = if b.is_instance_default {
                    (
                        "default storage".to_string(),
                        "/-/instance/storage".to_string(),
                    )
                } else {
                    let org = match registry.org_id {
                        Some(oid) => deps
                            .db
                            .org_by_id(oid)
                            .await?
                            .map(|o| o.slug)
                            .unwrap_or_default(),
                        None => String::new(),
                    };
                    (b.name.clone(), format!("/-/org/{org}/bindings/{}", b.id))
                };
                (list, label, href)
            }
            None => (Vec::new(), String::new(), String::new()),
        };
        Ok::<_, anyhow::Error>(console::serving_page(
            &session.email,
            registry,
            &session.csrf(),
            &frontends,
            &inherited,
            &inh_label,
            &inh_href,
            advertise_storage_frontend,
            mirror.as_ref(),
            notice,
            started,
        ))
    }
    .await;
    match result {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /{slug}/-/settings/serving` — add/delete a frontend or set/clear the
/// mirror config.
pub(crate) async fn serving_post(
    deps: ConsoleDeps,
    headers: HeaderMap,
    RequestStart(started): RequestStart,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    body: axum::body::Bytes,
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
    let fields = parse_form(&String::from_utf8_lossy(&body));
    serving_action(&deps, &session, &registry, &fields, started).await
}

/// Apply a serving/mirror mutation.
async fn serving_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    fields: &std::collections::HashMap<String, String>,
    started: Instant,
) -> Response {
    let field = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
    if let Err(resp) = check_csrf(session, field("csrf")) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    async fn audit(
        deps: &ConsoleDeps,
        session: &Session,
        registry: &RegistryRecord,
        action: &str,
        detail: &str,
    ) -> anyhow::Result<i64> {
        deps.db
            .record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                action,
                &registry.slug,
                None,
                None,
                None,
                Some(detail),
            )
            .await
    }

    match field("op") {
        "add-frontend" => {
            let domain = field("domain").trim();
            if domain.is_empty() {
                return (StatusCode::BAD_REQUEST, "domain is required").into_response();
            }
            let priority: i64 = field("consumer_priority").trim().parse().unwrap_or(100);
            let created = deps
                .db
                .create_frontend(
                    registry.id,
                    domain,
                    field("base_path").trim(),
                    match field("mode") {
                        "proxied" => "proxied",
                        _ => "direct",
                    },
                    field("serves_git") == "1",
                    field("serves_cache") == "1",
                    field("serves_web") == "1",
                    priority,
                    field("advertised") == "1",
                )
                .await;
            match created {
                Ok(_) => {}
                Err(err) => return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
            }
            if let Err(err) = audit(deps, session, registry, "frontend.add", domain).await {
                return internal(err);
            }
            serving_view(deps, session, registry, Some("Frontend added."), started).await
        }
        "edit-frontend" => {
            let Ok(id) = field("id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad frontend id").into_response();
            };
            match deps.db.list_frontends(registry.id).await {
                Ok(list) if list.iter().any(|f| f.id == id) => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such frontend").into_response(),
                Err(err) => return internal(err),
            }
            let priority: i64 = field("consumer_priority").trim().parse().unwrap_or(100);
            let updated = deps
                .db
                .update_frontend(
                    id,
                    field("domain").trim(),
                    field("base_path").trim(),
                    match field("mode") {
                        "proxied" => "proxied",
                        _ => "direct",
                    },
                    field("serves_git") == "1",
                    field("serves_cache") == "1",
                    field("serves_web") == "1",
                    priority,
                    field("advertised") == "1",
                )
                .await;
            if let Err(err) = updated {
                return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response();
            }
            if let Err(err) = audit(deps, session, registry, "frontend.edit", &id.to_string()).await
            {
                return internal(err);
            }
            serving_view(deps, session, registry, Some("Frontend updated."), started).await
        }
        "delete-frontend" => {
            let Ok(id) = field("id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad frontend id").into_response();
            };
            match deps.db.list_frontends(registry.id).await {
                Ok(list) if list.iter().any(|f| f.id == id) => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such frontend").into_response(),
                Err(err) => return internal(err),
            }
            if let Err(err) = deps.db.delete_frontend(id).await {
                return internal(err);
            }
            if let Err(err) =
                audit(deps, session, registry, "frontend.delete", &id.to_string()).await
            {
                return internal(err);
            }
            serving_view(deps, session, registry, Some("Frontend deleted."), started).await
        }
        "set-mirror" => {
            let upstream = field("upstream_url").trim();
            if upstream.is_empty() {
                return (StatusCode::BAD_REQUEST, "upstream URL is required").into_response();
            }
            // The hub fetches the upstream on the mirror schedule, so reject a
            // non-http(s) or local/internal origin (SSRF) at the write.
            if let Err(err) = crate::url_guard::is_safe_remote_url(upstream) {
                return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response();
            }
            let secs: i64 = field("schedule_secs").trim().parse().unwrap_or(3600);
            let r = deps
                .db
                .create_mirror_source(
                    registry.id,
                    upstream,
                    match field("mode") {
                        "pullthrough" => "pullthrough",
                        _ => "full",
                    },
                    field("verify") == "1",
                    secs,
                )
                .await;
            if let Err(err) = r {
                return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response();
            }
            if let Err(err) = audit(deps, session, registry, "mirror.set", upstream).await {
                return internal(err);
            }
            serving_view(
                deps,
                session,
                registry,
                Some("Mirror configuration saved."),
                started,
            )
            .await
        }
        "remove-mirror" => {
            if let Err(err) = deps.db.delete_mirror_source(registry.id).await {
                return internal(err);
            }
            if let Err(err) = audit(deps, session, registry, "mirror.remove", &registry.slug).await
            {
                return internal(err);
            }
            serving_view(deps, session, registry, Some("Stopped mirroring."), started).await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
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
    headers: &HeaderMap,
    page_number: usize,
    started: Instant,
) -> Response {
    if let Err(deny) = authorize_registry_read(deps, registry, headers).await {
        return *deny;
    }
    let roster = match deps.db.list_roster(registry.id).await {
        Ok(roster) => roster,
        Err(err) => return internal(err),
    };
    let can_manage = session
        .allows(
            &deps.db,
            Permission::KeysManage,
            &Scope::parse(&registry.slug),
        )
        .await;
    Html(console::keys_page(
        &session.email,
        registry,
        &roster,
        can_manage,
        page_number,
        started,
    ))
    .into_response()
}

/// `GET /{slug}/-/keys/rotate` — the rotation wizard.
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
    headers: &HeaderMap,
    started: Instant,
) -> Response {
    if let Err(deny) = authorize_registry_read(deps, registry, headers).await {
        return *deny;
    }
    Html(console::keys_rotate_page(&session.email, registry, started)).into_response()
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
    publishes_view(&deps, &session, &registry, &headers, started).await
}

/// Render the publish-pipeline view: visibility-gated.
async fn publishes_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
    started: Instant,
) -> Response {
    if let Err(deny) = authorize_registry_read(deps, registry, headers).await {
        return *deny;
    }
    let result = async {
        let status = deps.db.index_status(registry.id).await?;
        let releases = deps.db.list_releases(registry.id).await?;
        let audit: Vec<_> = deps
            .db
            .list_audit(&registry.slug)
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

/// `GET /{slug}/-/settings/config` — the git-backed config-edit page.
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

/// Builds the config-editor autofill suggestions: the registry's DB-linked
/// caches with each cache's consumer URL and whether it is already present in
/// the form's current `[caches]` (matched trailing-slash-normalized).
///
/// # Errors
///
/// Returns an error on database failure or when resolving a cache's consumer
/// URL fails.
async fn linked_cache_suggestions(
    deps: &ConsoleDeps,
    registry: &RegistryRecord,
    model: &crate::web::config_form::ConfigFormModel,
) -> anyhow::Result<Vec<console::LinkedCacheSuggestion>> {
    let present: std::collections::HashSet<String> = model
        .caches
        .iter()
        .map(|row| row.url.trim_end_matches('/').to_string())
        .collect();
    let mut suggestions = Vec::new();
    for link in deps.db.cache_links_for_registry(registry.id).await? {
        if let Some(cache) = deps.db.cache_by_id(link.cache_id).await? {
            if cache.deleted_at.is_none() {
                let url = crate::service::cache_consumer_url(&deps.db, &deps.external_url, &cache)
                    .await?;
                let present = present.contains(url.trim_end_matches('/'));
                suggestions.push(console::LinkedCacheSuggestion {
                    cache_slug: cache.slug,
                    consumer_url: url,
                    present,
                });
            }
        }
    }
    Ok(suggestions)
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
    let scope = Scope::parse(&registry.slug);
    let can_edit = session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await;
    let current = match current_registry_toml(deps, registry).await {
        Ok(toml) => toml,
        Err(err) => return internal(err),
    };
    // Auto-generate the structured form from the parsed config for editors.
    // A file the form can't represent (malformed, or carrying fields outside
    // the schema) and the read-only view both fall back to the raw-TOML page,
    // which shows the committed file verbatim so nothing is hidden or dropped.
    match crate::web::config_form::parse_model(&current) {
        Some(model) if can_edit => {
            // Autofill suggestions: the registry's DB-linked caches, each with
            // its consumer URL and whether that URL is already in the config the
            // form currently shows.
            let linked = match linked_cache_suggestions(deps, registry, &model).await {
                Ok(linked) => linked,
                Err(err) => return internal(err),
            };
            Html(console::registry_config_form_page(
                &session.email,
                registry,
                &session.csrf(),
                &model,
                can_edit,
                &linked,
                result,
                started,
            ))
            .into_response()
        }
        _ => Html(console::config_edit_page(
            &session.email,
            registry,
            &session.csrf(),
            &current,
            can_edit,
            result,
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
    let fetch = deps.surface.fetcher(registry).await?;
    Ok(
        crate::git::load_committed_file(fetch.as_ref(), head, "registry.toml")
            .await?
            .unwrap_or_default(),
    )
}

/// `POST /{slug}/-/settings/config` — submit a structured config change request.
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
    let scope = Scope::parse(&registry.slug);
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
            let linked = match linked_cache_suggestions(&deps, &registry, &model).await {
                Ok(linked) => linked,
                Err(err) => return internal(err),
            };
            Html(console::registry_config_form_page(
                &session.email,
                &registry,
                &session.csrf(),
                &model,
                true,
                &linked,
                None,
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
    let fetch = match deps.surface.fetcher(registry).await {
        Ok(fetch) => fetch,
        Err(err) => return internal(err),
    };
    let writer = match deps.surface_write.writer(registry).await {
        Ok(writer) => writer,
        Err(err) => return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    };
    let proposed = crate::gitwrite::propose_config_change(
        &deps.db,
        deps.sealer.as_ref(),
        fetch.as_ref(),
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

/// `GET /{slug}/-/changes` — the git-backed change-request list page.
///
/// Lists the registry's git-backed change requests with their file diffs and
/// promotion commands. Gated to `audit.read` (admin+), matching the access
/// matrix for the configuration/change surface.
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
    let filter = console::ChangesFilter::parse(query_value(&uri, "state").as_deref());
    changes_view(&deps, &session, &registry, filter, started).await
}

/// Render the change-request list page for a resolved registry.
///
/// Gated to `audit.read` (admin+). Renders the Open/Closed/All tabbed list; each
/// row links to the change's detail page.
async fn changes_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    filter: console::ChangesFilter,
    started: Instant,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&deps.db, Permission::AuditRead, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "audit.read required").into_response();
    }

    let result = async {
        let changesets = deps.db.list_changesets(&registry.slug).await?;
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

/// `GET /{slug}/-/changes/{id}` — the change-request detail (review) page.
///
/// Renders the PR-style Conversation / Diff / Checks views for one git-backed
/// change request. Gated to `audit.read`; a change whose scope is not contained
/// by the resolved registry (or that is not a git-backed change request) 404s,
/// so a registry's URL can only reach its own changes.
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
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&deps.db, Permission::AuditRead, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "audit.read required").into_response();
    }
    let can_close = session
        .allows(&deps.db, Permission::RegistryConfigure, &scope)
        .await;

    let result = async {
        let Some(cs) = deps.db.changeset(change_id).await? else {
            return Ok(None);
        };
        // Scope guard: only this registry's own git-backed change requests.
        if cs.git_ref.is_none() || !scope.contains(&Scope::parse(&cs.scope)) {
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

/// Loads a change request for a mutating action: resolves the registry, checks
/// `perm`, validates CSRF, and confirms the change is one of this registry's own
/// git-backed change requests. Returns the loaded changeset on success, or the
/// error response to return.
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
    if let Err(resp) = check_csrf(&session, csrf) {
        return Err(*resp);
    }
    let scope = Scope::parse(&registry.slug);
    if !session.allows(&deps.db, perm, &scope).await {
        return Err((StatusCode::FORBIDDEN, "insufficient permission").into_response());
    }
    let Some(cs) = deps.db.changeset(change_id).await.map_err(internal)? else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    if cs.git_ref.is_none() || !scope.contains(&Scope::parse(&cs.scope)) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    Ok((session, registry, cs))
}

/// A 303 redirect back to a change's detail page (post/redirect/get).
fn redirect_to_change(slug: &str, change_id: &str) -> Response {
    Redirect::to(&format!("/{slug}/-/changes/{change_id}")).into_response()
}

/// `POST /{slug}/-/changes/{id}/comment` — post a discussion comment.
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

/// `POST /{slug}/-/changes/{id}/review` — submit an advisory review.
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

/// `POST /{slug}/-/changes/{id}/close` — withdraw an open draft change request.
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

/// `POST /{slug}/-/changes/{id}/reopen` — reopen a closed change request.
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
    use super::registry_delete_target;

    #[test]
    fn registry_delete_returns_to_owning_org_inventory() {
        assert_eq!(
            registry_delete_target(Some("acme")),
            "/-/org/acme/registries"
        );
        assert_eq!(registry_delete_target(None), "/");
    }
}
