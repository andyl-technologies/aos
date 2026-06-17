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
//! The pre-auth rate-limited login paths ([`login_form`], [`login_submit`],
//! [`login_password`]) live here too: instead of the native `ConnectInfo` peer
//! socket and a reverse-proxy trust flag, they read the connecting client's IP
//! from the runtime-neutral [`CLIENT_IP_HEADER`] each shell stamps on ingress
//! (RFC-0004 Phase 5, console-dedup stage D). The remaining native-only handlers
//! — the device-approval `/activate` surface and passkey assertion `begin` (both
//! still keyed on the native peer), the OIDC flow (outbound `reqwest`), and the
//! git-backed config/change-request flows — stay in the native hub, which mounts
//! them alongside this router.
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

use std::time::Instant;

use axum::extract::{Form, Path, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use base64::Engine as _;

use crate::auth::session::{set_cookie_header, ABSOLUTE_LIFETIME_SECS, COOKIE_NAME};
use crate::config::{self, MembershipChange};
use crate::db::{Database, OrgRecord, RegistryRecord, SessionAuth as DbSession};
use crate::domain::{iam, Permission, Principal, Role, Scope};
use crate::web::console::ports::ConsoleDeps;
use crate::web::console_render as console;
use crate::web::csrf::{connect_or_csrf_ok, mint_csrf_token};
use crate::web::session::resolve_session_from_headers;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

// -- shared helpers ---------------------------------------------------------

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
/// window is refused with a `403` asking the user to sign in again.
///
/// # Errors
///
/// Returns a boxed `403` response when the session is not sudo.
fn require_sudo(session: &Session) -> Result<(), Box<Response>> {
    if session.auth.is_sudo(crate::clock::now_unix_secs()) {
        Ok(())
    } else {
        Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "Re-authenticate to perform this action: sign in again, then retry.",
            )
                .into_response(),
        ))
    }
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
/// The pre-auth login handlers ([`login_submit`], [`login_password`]) rate-limit
/// on the connecting client's IP, but the connecting peer address and the
/// reverse-proxy trust model are *runtime-specific* (a native `ConnectInfo`
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
pub(crate) async fn login_form(_deps: ConsoleDeps) -> Response {
    let nonce = crate::auth::webauthn::new_challenge();
    let html = console::login_page(None, Some(&nonce), Instant::now());
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
    Form(form): Form<LoginForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Html(console::login_page(
            Some("Enter a valid email address."),
            None,
            Instant::now(),
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
        return Html(console::login_sso_page(
            &email,
            &org_slug,
            &start,
            Instant::now(),
        ))
        .into_response();
    }
    let secret = match deps.db.create_magic_link(&email).await {
        Ok(secret) => secret,
        Err(err) => return internal(err),
    };
    let link = format!(
        "{}/auth/magic?token={secret}",
        deps.external_url.trim_end_matches('/'),
    );
    if let Err(err) = deps.mailer.send_magic_link(&email, &link) {
        tracing::warn!(error = %format!("{err:#}"), "magic link delivery failed");
    }
    // In `--dev` mode the mailer only logs, so surface the link on the page so a
    // local operator can follow it (the native hub keyed this off `LogMailer`).
    let dev_link = deps.dev.then_some(link.as_str());
    Html(console::login_sent_page(&email, dev_link, Instant::now())).into_response()
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
    Form(form): Form<PasswordLoginForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    // The single generic failure render, used for every rejection path so the
    // endpoint is not an account-existence oracle.
    let invalid = || {
        Html(console::login_page(
            Some("Invalid email or password."),
            None,
            Instant::now(),
        ))
        .into_response()
    };
    if email.is_empty() || !email.contains('@') || form.password.is_empty() {
        return invalid();
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
    let cookie = match deps
        .db
        .create_session(user_id, ABSOLUTE_LIFETIME_SECS, 1)
        .await
    {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
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
    Query(query): Query<MagicQuery>,
) -> Response {
    let email = match deps.db.consume_magic_link(&query.token).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            return Html(console::login_page(
                Some("That sign-in link is invalid or expired. Request a new one."),
                None,
                Instant::now(),
            ))
            .into_response()
        }
        Err(err) => return internal(err),
    };
    let user_id = match deps.db.find_or_create_user(&email).await {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    let cookie = match deps
        .db
        .create_session(user_id, ABSOLUTE_LIFETIME_SECS, 1)
        .await
    {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
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

/// `GET /account` — the profile page (email, sessions, tokens, passkeys).
pub(crate) async fn account(deps: ConsoleDeps, headers: HeaderMap) -> Response {
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
        Instant::now(),
    ))
    .into_response()
}

/// `POST /account/password` body: the CSRF token and the new password.
#[derive(serde::Deserialize)]
pub(crate) struct SetPasswordForm {
    #[serde(default)]
    csrf: String,
    password: String,
}

/// `POST /account/password` — set or change the logged-in user's password.
///
/// Session-authed, CSRF-protected, and **sudo-gated**. A member of an
/// SSO-enforced org is refused (a local password would bypass IdP
/// deprovisioning). On success it revokes every session, then mints a fresh
/// sudo session for this browser.
pub(crate) async fn account_set_password(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<SetPasswordForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(&session) {
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
                    Instant::now(),
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
            Instant::now(),
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
    let cookie = match deps
        .db
        .create_session(session.auth.user_id, ABSOLUTE_LIFETIME_SECS, 1)
        .await
    {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
        Err(err) => return internal(err),
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to("/account")).into_response()
}

/// `POST /account/sessions/revoke-all` — sign out of every browser.
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

/// `GET /account/passkeys` — list the user's passkeys and offer to add one.
pub(crate) async fn passkeys(deps: ConsoleDeps, headers: HeaderMap) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let creds = match deps.db.list_user_credentials(session.auth.user_id).await {
        Ok(c) => c,
        Err(err) => return internal(err),
    };
    let nonce = crate::auth::webauthn::new_challenge();
    let html = console::passkeys_page(
        &session.email,
        &session.csrf(),
        &creds,
        &nonce,
        Instant::now(),
    );
    passkey_html_response(html, &nonce)
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

/// `POST /account/passkeys/begin` — stage a registration challenge (JSON).
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

/// `POST /account/passkeys/finish` — verify + persist the new credential.
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
    let user_id =
        match crate::auth::webauthn::finish_assertion(&deps.db, &rp.id, &rp.origin, &response).await
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
    let cookie = match deps
        .db
        .create_session(user_id, ABSOLUTE_LIFETIME_SECS, 1)
        .await
    {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
        Err(err) => return internal(err),
    };
    (
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "ok": true })),
    )
        .into_response()
}

// -- orgs -------------------------------------------------------------------

/// `GET /-/orgs` — the user's org list.
pub(crate) async fn orgs(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
            Instant::now(),
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
    Path(org_slug): Path<String>,
    Query(pages): Query<DashboardPages>,
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
        let can_audit = session.allows(&deps.db, Permission::AuditRead, &scope).await;
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
            &bindings,
            can_manage,
            can_audit,
            can_configure,
            can_delete,
            owner_count,
            pages.registries(),
            pages.members(),
            Instant::now(),
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
    Path(org_slug): Path<String>,
    Query(params): Query<PageQuery>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = Scope::parse(&org_slug);
    if !session.allows(&deps.db, Permission::AuditRead, &scope).await {
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
            Instant::now(),
        )))
    }
    .await;
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
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
    if let Err(resp) = require_sudo(&session) {
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
        let _ = org;
        Ok::<Result<(), MembershipReject>, anyhow::Error>(Ok(()))
    }
    .await;
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
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
    if let Err(resp) = require_sudo(&session) {
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
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
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
    if let Err(resp) = require_sudo(&session) {
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
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(Err(reject)) => reject.into_response(),
        Err(err) if crate::db::is_last_owner_error(&err) => {
            MembershipReject::LastOwner.into_response()
        }
        Err(err) => internal(err),
    }
}

// -- create organization ----------------------------------------------------

/// `GET /new` — the create-organization form.
pub(crate) async fn new_org_form(deps: ConsoleDeps, headers: HeaderMap) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    match may_create_org(&deps.db, &session).await {
        Ok(true) => Html(console::new_org_page(
            &session.email,
            &session.csrf(),
            None,
            Instant::now(),
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
            Instant::now(),
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
        Ok(true) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
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
        Ok(Some(Ok(()))) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
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
        let in_use = deps
            .db
            .list_registries()
            .await?
            .into_iter()
            .any(|r| r.storage_binding_id == Some(binding.id));
        if in_use {
            return Ok(Some(Err("binding still in use by a registry")));
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
        Ok(Some(Ok(()))) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(Some(Err(msg))) => (StatusCode::CONFLICT, msg).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/bindings` form: a name and an absolute root path.
#[derive(serde::Deserialize)]
pub(crate) struct NewBindingForm {
    #[serde(default)]
    csrf: String,
    name: String,
    root: String,
}

/// `POST /-/org/{org}/bindings` — create a `local_fs` storage binding.
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
    let path = std::path::Path::new(root);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return (
            StatusCode::BAD_REQUEST,
            "root must be an absolute path with no '..' components",
        )
            .into_response();
    }
    let result = async {
        let Some(org) = deps.db.org_by_slug(&org_slug).await? else {
            return Ok(false);
        };
        deps.db
            .create_storage_binding(org.id, name, "local_fs", root)
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
        Ok::<_, anyhow::Error>(true)
    }
    .await;
    match result {
        Ok(true) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

/// `GET /-/org/{org}/registries/new` — the create-registry form.
pub(crate) async fn org_new_registry_form(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
            Instant::now(),
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
            Instant::now(),
        ))
        .into_response()
    }

    let name = form.name.trim();
    if name.is_empty() {
        return reject(&deps, &org, &session, "Registry name is required.").await;
    }
    let visibility = match form.visibility.trim() {
        "" => "private",
        v @ ("public" | "internal" | "private") => v,
        _ => return reject(&deps, &org, &session, "Invalid visibility.").await,
    };
    let binding_id = match deps
        .db
        .storage_binding_by_name(org.id, form.binding.trim())
        .await
    {
        Ok(Some(b)) => b.id,
        Ok(None) => return reject(&deps, &org, &session, "Choose a storage binding.").await,
        Err(err) => return internal(err),
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
            Some(binding_id),
            prefix,
            &trust_keys,
            require_signatures,
        )
        .await;
    match created {
        Ok(_) => {}
        Err(err) => return reject(&deps, &org, &session, &format!("{err:#}")).await,
    }
    let canonical = match deps.db.registry_by_scope(&org.slug, project_path, name).await {
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
    if let Err(resp) = require_sudo(&session) {
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
        let deleted = deps.db.soft_delete_org(org.id, ORG_DELETE_GRACE_SECS).await?;
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
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_instance_settings(&deps, &session, None).await
}

/// Render the instance-settings page; instance-admin only.
async fn render_instance_settings(
    deps: &ConsoleDeps,
    session: &Session,
    notice: Option<&str>,
) -> Response {
    if !session
        .allows(&deps.db, Permission::IamAdmin, &Scope::parse(""))
        .await
    {
        return (StatusCode::FORBIDDEN, "instance admin required").into_response();
    }
    let policy = match deps.db.signup_policy().await {
        Ok(p) => p,
        Err(err) => return internal(err),
    };
    Html(console::instance_settings_page(
        &session.email,
        &session.csrf(),
        policy,
        notice,
        Instant::now(),
    ))
    .into_response()
}

/// `POST /-/instance` form: the instance signup policy.
#[derive(serde::Deserialize)]
pub(crate) struct InstanceSettingsForm {
    #[serde(default)]
    csrf: String,
    signup_policy: String,
}

/// `POST /-/instance` — update the instance signup policy (instance admins).
pub(crate) async fn instance_settings_action(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Form(form): Form<InstanceSettingsForm>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if !session
        .allows(&deps.db, Permission::IamAdmin, &Scope::parse(""))
        .await
    {
        return (StatusCode::FORBIDDEN, "instance admin required").into_response();
    }
    let policy = crate::db::SignupPolicy::parse(&form.signup_policy);
    if let Err(err) = deps.db.set_signup_policy(policy).await {
        return internal(err);
    }
    if let Err(err) = deps
        .db
        .record_audit(
            "user",
            Some(session.auth.user_id),
            &session.email,
            "instance.signup_policy",
            "",
            None,
            None,
            None,
            Some(policy.as_str()),
        )
        .await
    {
        return internal(err);
    }
    render_instance_settings(&deps, &session, Some("Signup policy saved.")).await
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
    registry_settings_view(&deps, &session, &registry, None).await
}

/// Render the registry settings landing page.
async fn registry_settings_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<&str>,
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
        let can_delete = session.allows(&deps.db, Permission::IamAdmin, &scope).await;
        let binding_ref = binding
            .as_ref()
            .map(|(n, r, p)| (n.as_str(), r.as_str(), p.as_str()));
        Ok::<_, anyhow::Error>(console::registry_settings_page(
            &session.email,
            registry,
            &session.csrf(),
            binding_ref,
            can_delete,
            result,
            Instant::now(),
        ))
    }
    .await;
    match result_outcome {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
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
    registry_visibility_action(&deps, &session, &registry, &form.csrf, &form.visibility).await
}

/// The visibility-change action.
async fn registry_visibility_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    visibility: &str,
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
    registry_settings_view(deps, session, &updated, Some(change_id.0.as_str())).await
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
    registry_delete_action(&deps, &session, &registry, &form.csrf, &form.confirm).await
}

/// The registry-delete action.
async fn registry_delete_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    confirm: &str,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(session) {
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
                Some(org) => format!("/-/org/{}", org.slug),
                None => "/".to_string(),
            },
            None => "/".to_string(),
        };
        Ok::<_, anyhow::Error>(target)
    }
    .await;
    match result {
        Ok(target) => Redirect::to(&target).into_response(),
        Err(err) => internal(err),
    }
}

// -- registry tokens --------------------------------------------------------

/// `GET /{slug}/-/settings/tokens` — the caller's tokens at the registry.
pub(crate) async fn tokens(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    tokens_view(&deps, &session, &registry, &headers, page.page()).await
}

/// Render the tokens page (read path): visibility-gated, no result banner.
async fn tokens_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
    page_number: usize,
) -> Response {
    if let Err(deny) = authorize_registry_read(deps, registry, headers).await {
        return *deny;
    }
    render_tokens(deps, session, registry, None, page_number).await
}

/// The token-create action: CSRF + TokensSelf gate, mint, show secret once.
async fn tokens_create_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    want_read: bool,
    want_publish: bool,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(session) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if !session.allows(&deps.db, Permission::TokensSelf, &scope).await {
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
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = ensure_owns_token(deps, session, token_id).await {
        return *resp;
    }
    if rotate {
        if let Err(resp) = require_sudo(session) {
            return *resp;
        }
        match deps.db.rotate_token(token_id).await {
            Ok(Some((_, secret))) => {
                render_tokens(deps, session, registry, Some(("Token rotated", &secret)), 1).await
            }
            Ok(None) => {
                Redirect::to(&format!("/{}/-/settings/tokens", registry.slug)).into_response()
            }
            Err(err) => internal(err),
        }
    } else {
        match deps.db.revoke_token(token_id).await {
            Ok(()) => {
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
) -> Response {
    let scope = Scope::parse(&registry.slug);
    let can_create = session.allows(&deps.db, Permission::TokensSelf, &scope).await;
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
        Instant::now(),
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
    tokens_modify_action(&deps, &session, &registry, &form.csrf, &form.token_id, false).await
}

/// `POST /{slug}/-/settings/tokens/rotate` — rotate one of the caller's tokens.
pub(crate) async fn tokens_rotate(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    tokens_modify_action(&deps, &session, &registry, &form.csrf, &form.token_id, true).await
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
    render_channel_console(&deps, &session, &registry, &name, None, None).await
}

/// Render the channel console.
async fn render_channel_console(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    name: &str,
    prepared: Option<(&str, &str)>,
    advanced: Option<&str>,
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
            Instant::now(),
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
    )
    .await
}

/// `POST /{slug}/-/channels/{name}/advance` — directly advance a hosted-key
/// channel.
pub(crate) async fn channel_advance_direct(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    )
    .await
}

/// The direct hosted-key advance action: sign and apply the advance through the
/// [`ChannelAdvancer`](super::ports::ChannelAdvancer) port (or fall back to a
/// prepared operation when no hosted key is bound).
async fn advance_direct_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    name: &str,
    csrf: &str,
    release: &str,
    partitions: Option<&str>,
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
        return channel_advance_action(deps, session, registry, name, csrf, release, partitions)
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
    let result = deps
        .advancer
        .advance(registry, name, release, count, when)
        .await;
    match result {
        Ok(outcome) => {
            let message = format!(
                "Advanced {} to {} · {} partition(s) moved · {}% rolled out",
                outcome.channel, outcome.release, outcome.moved, outcome.rollout_percent,
            );
            render_channel_console(deps, session, registry, name, None, Some(&message)).await
        }
        Err(err) => {
            (StatusCode::BAD_REQUEST, format!("advance failed: {err:#}")).into_response()
        }
    }
}

// -- hosted signing keys ----------------------------------------------------

/// `GET /-/org/{org}/keys` — the org hosted-key enrollment page.
pub(crate) async fn org_keys(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_keys(&deps, &session, &org_slug, None).await
}

/// Render the org hosted-keys page.
async fn render_org_keys(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    created: Option<&str>,
) -> Response {
    let scope = Scope::parse(org_slug);
    if !session.allows(&deps.db, Permission::KeysManage, &scope).await {
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
            Instant::now(),
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
    if let Err(resp) = require_sudo(&session) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session.allows(&deps.db, Permission::KeysManage, &scope).await {
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
            render_org_keys(&deps, &session, &org_slug, Some(&public)).await
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
            if let Err(err) = deps.db.set_registry_hosted_key(registry.id, hosted_key_id).await {
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
            render_org_keys(&deps, &session, &org_slug, None).await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- webhooks ---------------------------------------------------------------

/// `GET /-/org/{org}/webhooks` — the org webhook management page.
pub(crate) async fn org_webhooks(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_webhooks(&deps, &session, &org_slug, None).await
}

/// Render the org webhooks page.
async fn render_org_webhooks(
    deps: &ConsoleDeps,
    session: &Session,
    org_slug: &str,
    created_secret: Option<&str>,
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
            Instant::now(),
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
            let known: Vec<&str> = console::WEBHOOK_EVENT_TYPES.iter().map(|(e, _)| *e).collect();
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
            render_org_webhooks(&deps, &session, &org_slug, None).await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- single sign-on (OIDC IdP + email domains) ------------------------------

/// `GET /-/org/{org}/sso` — the org SSO (OIDC IdP + domains) page.
pub(crate) async fn org_sso(
    deps: ConsoleDeps,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&deps, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_sso(&deps, &session, &org_slug, None).await
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
            Instant::now(),
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
    if let Err(resp) = require_sudo(&session) {
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
            render_org_sso(&deps, &session, &org_slug, Some("Identity provider saved.")).await
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
            render_org_sso(&deps, &session, &org_slug, Some("Identity provider removed.")).await
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
                    return (StatusCode::NOT_FOUND, "domain not claimed by this org").into_response()
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
            render_org_sso(&deps, &session, &org_slug, Some(&format!("Verified {domain}."))).await
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
            render_org_sso(&deps, &session, &org_slug, Some(&format!("Removed {domain}."))).await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- serving frontends + mirror ---------------------------------------------

/// `GET /{slug}/-/settings/serving` — the serving & mirror management page.
pub(crate) async fn serving(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    serving_view(&deps, &session, &registry, None).await
}

/// Render the serving & mirror page.
async fn serving_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    notice: Option<&str>,
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
        Ok::<_, anyhow::Error>(console::serving_page(
            &session.email,
            registry,
            &session.csrf(),
            &frontends,
            mirror.as_ref(),
            notice,
            Instant::now(),
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
    serving_action(&deps, &session, &registry, &fields).await
}

/// Apply a serving/mirror mutation.
async fn serving_action(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    fields: &std::collections::HashMap<String, String>,
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
            serving_view(deps, session, registry, Some("Frontend added.")).await
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
            if let Err(err) = audit(deps, session, registry, "frontend.delete", &id.to_string()).await
            {
                return internal(err);
            }
            serving_view(deps, session, registry, Some("Frontend deleted.")).await
        }
        "set-mirror" => {
            let upstream = field("upstream_url").trim();
            if upstream.is_empty() {
                return (StatusCode::BAD_REQUEST, "upstream URL is required").into_response();
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
            serving_view(deps, session, registry, Some("Mirror configuration saved.")).await
        }
        "remove-mirror" => {
            if let Err(err) = deps.db.delete_mirror_source(registry.id).await {
                return internal(err);
            }
            if let Err(err) = audit(deps, session, registry, "mirror.remove", &registry.slug).await {
                return internal(err);
            }
            serving_view(deps, session, registry, Some("Stopped mirroring.")).await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- keys -------------------------------------------------------------------

/// `GET /{slug}/-/keys` — the key roster management page.
pub(crate) async fn keys(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    keys_view(&deps, &session, &registry, &headers, page.page()).await
}

/// Render the key roster page: visibility-gated.
async fn keys_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
    page_number: usize,
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
        Instant::now(),
    ))
    .into_response()
}

/// `GET /{slug}/-/keys/rotate` — the rotation wizard.
pub(crate) async fn keys_rotate(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    keys_rotate_view(&deps, &session, &registry, &headers).await
}

/// Render the rotation wizard: visibility-gated.
async fn keys_rotate_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Response {
    if let Err(deny) = authorize_registry_read(deps, registry, headers).await {
        return *deny;
    }
    Html(console::keys_rotate_page(
        &session.email,
        registry,
        Instant::now(),
    ))
    .into_response()
}

// -- publishes --------------------------------------------------------------

/// `GET /{slug}/-/publishes` — the publish-pipeline status view.
pub(crate) async fn publishes(
    deps: ConsoleDeps,
    headers: HeaderMap,
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
    publishes_view(&deps, &session, &registry, &headers).await
}

/// Render the publish-pipeline view: visibility-gated.
async fn publishes_view(
    deps: &ConsoleDeps,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
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
            Instant::now(),
        ))
    }
    .await;
    match result {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}
