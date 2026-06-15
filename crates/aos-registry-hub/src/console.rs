//! The authenticated producer console: handlers and routes (RFC-0004
//! phase-3b).
//!
//! This module owns the *cookie-authenticated* surface — session login, the
//! account profile, RFC 8628 device approval, the org/project dashboards,
//! and the per-registry management pages (tokens, channel rollout, keys,
//! publishes). The page *rendering* lives in [`crate::ui::console`]; this
//! module is the request edge: session extraction, IAM gating, CSRF
//! enforcement on every `POST`, and the plain form/redirect flows that keep
//! the console no-JS.
//!
//! # Channel rollout: prepared vs. hosted-key (phase 4a)
//!
//! The channel rollout console renders one of two modes depending on whether
//! the registry has a bound hosted signing key. With **no hosted key**
//! (BYO-key, the default), an advance records a *prepared operation* — a draft
//! change-set — and echoes the `apr channel advance --from-hub` command the
//! maintainer signs and pushes locally. With a **hosted key**, the advance
//! form posts to [`channel_advance_direct`], which signs the partition tags
//! with the hub-held key ([`crate::signing::advance_channel`]), writes them to
//! the surface, re-indexes, and audits the advance. Hosted keys are enrolled
//! and attached to registries from the org page at `/-/org/{org}/keys`
//! ([`org_keys`]), gated to org admins.
//!
//! # CSRF
//!
//! Every mutating handler here is reached with an ambient session cookie, so
//! it is CSRF-able. Each form embeds a per-session synchronizer token
//! ([`crate::auth::extract::mint_csrf_token`]); the handler verifies it with
//! [`crate::auth::extract::connect_or_csrf_ok`] and answers `403` on a bad or
//! missing token. This wires the CSRF helper that phase 2 defined but left
//! unwired.
//!
//! # Authorization
//!
//! Page gating uses the session user's *current* effective grants
//! ([`crate::db::Database::effective_scopes`]) through
//! [`crate::domain::iam::allow`]. An unauthorized read of a private resource
//! returns `404` (existence is never disclosed); a forbidden mutation
//! returns `403`.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;

use crate::auth::extract::{connect_or_csrf_ok, mint_csrf_token};
use crate::auth::session::{set_cookie_header, ABSOLUTE_LIFETIME_SECS, COOKIE_NAME};
use crate::config::{self, MembershipChange};
use crate::db::{Database, RegistryRecord, SessionAuth as DbSession};
use crate::domain::{iam, Permission, Principal, Role, Scope};
use crate::server::{
    authorize_registry_read, internal, resolve_by_prefix, session_secret_from_cookies, AppState,
};
use crate::ui::console;

/// The console routes, merged into the main router by [`crate::server::router`].
///
/// Top-level static prefixes (`/login`, `/logout`, `/account`, `/activate`,
/// `/auth/magic`, `/-/orgs`, `/-/org/...`) win over the registry catch-all by
/// axum's static-over-dynamic precedence. The per-registry settings routes
/// are registered on the flat `/{slug}/...` shape; nested registries reach
/// the read-only console pages through the `/-/` resolver.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login", get(login_form).post(login_submit))
        .route("/login/password", post(login_password))
        .route("/auth/magic", get(magic_consume))
        .route("/auth/sso", post(login_sso))
        .route("/auth/oidc/start", get(oidc_start))
        .route("/auth/oidc/callback", get(oidc_callback))
        .route("/logout", get(logout))
        .route("/account", get(account))
        .route("/account/password", post(account_set_password))
        .route(
            "/account/sessions/revoke-all",
            post(account_revoke_all_sessions),
        )
        // Passkeys / WebAuthn (RFC-0004). The registration ceremony is
        // session-authed (and CSRF-protected); the assertion ceremony is the
        // pre-auth login path.
        .route("/account/passkeys", get(passkeys))
        .route("/account/passkeys/begin", post(passkeys_begin))
        .route("/account/passkeys/finish", post(passkeys_finish))
        .route("/auth/passkey/begin", post(passkey_login_begin))
        .route("/auth/passkey/finish", post(passkey_login_finish))
        .route("/activate", get(activate_form).post(activate_submit))
        .route("/new", get(new_org_form).post(new_org_submit))
        .route("/-/orgs", get(orgs))
        .route("/-/org/{org}", get(org_dashboard))
        .route("/-/org/{org}/audit", get(org_audit))
        .route("/-/org/{org}/members", post(org_invite_member))
        .route("/-/org/{org}/members/remove", post(org_remove_member))
        .route("/-/org/{org}/projects", post(org_create_project))
        .route("/-/org/{org}/bindings", post(org_create_binding))
        .route("/-/org/{org}/registries/new", get(org_new_registry_form))
        .route("/-/org/{org}/registries", post(org_create_registry))
        .route("/-/org/{org}/delete", post(org_delete))
        .route("/{slug}/-/settings", get(registry_settings))
        .route("/{slug}/-/settings/visibility", post(registry_visibility))
        .route("/{slug}/-/settings/delete", post(registry_delete))
        .route(
            "/{slug}/-/settings/serving",
            get(serving).post(serving_post),
        )
        .route("/{slug}/-/settings/tokens", get(tokens).post(tokens_create))
        .route("/{slug}/-/settings/tokens/revoke", post(tokens_revoke))
        .route("/{slug}/-/settings/tokens/rotate", post(tokens_rotate))
        .route(
            "/{slug}/-/settings/config",
            get(config_edit).post(config_submit),
        )
        .route("/{slug}/-/changes", get(changes))
        .route(
            "/{slug}/-/channels/{name}/console",
            get(channel_console).post(channel_advance),
        )
        .route(
            "/{slug}/-/channels/{name}/advance",
            post(channel_advance_direct),
        )
        .route("/-/org/{org}/keys", get(org_keys).post(org_keys_action))
        .route(
            "/-/org/{org}/webhooks",
            get(org_webhooks).post(org_webhooks_action),
        )
        .route("/-/org/{org}/sso", get(org_sso).post(org_sso_action))
        .route("/-/org/{org}/projects/delete", post(org_delete_project))
        .route("/-/org/{org}/bindings/delete", post(org_delete_binding))
        .route("/-/org/{org}/members/role", post(org_member_role))
        .route(
            "/-/instance",
            get(instance_settings).post(instance_settings_action),
        )
        .route("/{slug}/-/keys", get(keys))
        .route("/{slug}/-/keys/rotate", get(keys_rotate))
        .route("/{slug}/-/publishes", get(publishes))
}

// -- session helpers --------------------------------------------------------

/// A resolved session: the secret (for CSRF minting), the user row, and the
/// user's email.
struct Session {
    secret: String,
    auth: DbSession,
    email: String,
}

/// Load and validate the request's session, or return a redirect to `/login`.
///
/// The producer console is human-only; an anonymous or invalid cookie is
/// bounced to the login page rather than 401'd, so a logged-out click lands
/// somewhere useful.
fn require_session(state: &AppState, headers: &HeaderMap) -> Result<Session, Box<Response>> {
    let Some(secret) = session_secret_from_cookies(headers) else {
        return Err(Box::new(Redirect::to("/login").into_response()));
    };
    let auth = match state.db.validate_session(&secret) {
        Ok(Some(auth)) => auth,
        Ok(None) => return Err(Box::new(Redirect::to("/login").into_response())),
        Err(err) => return Err(Box::new(internal(err))),
    };
    let email = match state.db.user_email(auth.user_id) {
        Ok(Some(email)) => email,
        Ok(None) => return Err(Box::new(Redirect::to("/login").into_response())),
        Err(err) => return Err(Box::new(internal(err))),
    };
    Ok(Session {
        secret,
        auth,
        email,
    })
}

impl Session {
    /// This session user's principal.
    fn principal(&self) -> Principal {
        Principal::user(self.auth.user_id)
    }

    /// The session's current effective grants.
    fn grants(&self, db: &Database) -> anyhow::Result<Vec<(Scope, Role)>> {
        db.effective_scopes(self.principal())
    }

    /// Whether this session may `perm` at `scope` under its current grants.
    fn allows(&self, db: &Database, perm: Permission, scope: &Scope) -> bool {
        match self.grants(db) {
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
/// The most destructive operations (password change, registry/org deletion)
/// gate on this: a session is sudo only when it was minted from a strong
/// re-authentication and that authentication is within
/// [`SUDO_WINDOW_SECS`](crate::auth::session::SUDO_WINDOW_SECS) of now (see
/// [`SessionAuth::is_sudo`](crate::db::SessionAuth::is_sudo)). A session that
/// has fallen out of the window is refused with a `403` and a message asking
/// the user to sign in again; the no-JS console has no in-place re-auth modal,
/// so re-running the login flow (which mints a fresh sudo session) is the path
/// back in.
fn require_sudo(session: &Session) -> Result<(), Box<Response>> {
    if session.auth.is_sudo(crate::server::now_secs()) {
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

// -- login + magic link -----------------------------------------------------

/// `GET /login` — the email-first login form, plus the passkey sign-in button.
///
/// Sets a per-request `script-src 'nonce-…'` CSP so the page's first-party
/// passkey script (driving `navigator.credentials.get`) runs while every other
/// inline script stays blocked.
async fn login_form(State(_state): State<Arc<AppState>>) -> Response {
    let nonce = crate::auth::webauthn::new_challenge();
    let html = console::login_page(None, Some(&nonce), Instant::now());
    passkey_html_response(html, &nonce)
}

/// `POST /login` body: the email to send a magic link to.
#[derive(serde::Deserialize)]
struct LoginForm {
    email: String,
}

/// Resolve the org whose **verified** domain captures `email`, together with
/// whether that org has an OIDC IdP configured and enforces SSO.
///
/// Returns `(org_slug, enforce_sso)` when the email's domain is captured by an
/// org *and* that org has an IdP; `None` otherwise (no capture, or a captured
/// domain whose org has no IdP — which falls back to magic links).
fn sso_target(state: &AppState, email: &str) -> Option<(String, bool)> {
    let domain = email.rsplit_once('@').map(|(_, d)| d.to_lowercase())?;
    let org_id = state.db.org_for_domain(&domain).ok().flatten()?;
    let config = state.db.idp_config(org_id).ok().flatten()?;
    let org = state.db.org_by_id(org_id).ok().flatten()?;
    Some((org.slug, config.enforce_sso))
}

/// Decide whether a user is **subject to SSO enforcement**, returning the org
/// slug to redirect them into when they are.
///
/// A user is captured by an org two ways — and *either* binds them to the IdP:
///
/// 1. **Verified domain.** The org's verified email domain matches the user's
///    address (the same rule [`sso_target`] uses for the magic-link path).
/// 2. **Membership.** The user holds a membership grant under the org — the
///    top-level segment of each membership scope is the org slug.
///
/// If *any* such org has `enforce_sso = true` on its OIDC IdP config, the user
/// must authenticate through that IdP: this returns `Some(org_slug)`, the org
/// to begin OIDC against (feed it to [`sso_start_path`]). Otherwise it returns
/// `None` and the local credential paths (magic link, password, passkey) stay
/// available.
///
/// This is the single source of truth shared by every credential path so the
/// invariant holds uniformly: the users forced to SSO at the magic-link entry
/// point are forced everywhere, and cannot mint a local credential that would
/// outlive their IdP account (defeating deprovisioning / conditional access).
///
/// `user_id` is the membership anchor; pass `None` on the pre-auth email-only
/// paths where the user row may not exist yet (the verified-domain rule still
/// applies, and a brand-new user holds no memberships).
///
/// # Errors
///
/// Returns an error only on an unexpected database failure while listing the
/// user's memberships; a missing org or IdP config is not an error (the org
/// simply does not enforce SSO for this user).
fn sso_enforced_for(
    state: &AppState,
    email: &str,
    user_id: Option<i64>,
) -> anyhow::Result<Option<String>> {
    // Rule 1: the user's verified email domain captures an SSO-enforcing org.
    if let Some((org_slug, true)) = sso_target(state, email) {
        return Ok(Some(org_slug));
    }
    // Rule 2: any org the user is a member of enforces SSO. The org slug is the
    // top-level segment of the membership scope (e.g. `acme` for `acme/cdn`).
    if let Some(user_id) = user_id {
        let principal = Principal::user(user_id);
        let mut seen_slugs = std::collections::HashSet::new();
        for (scope, _role) in state
            .db
            .list_memberships_for(principal.kind.as_str(), principal.id)?
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
            let Some(org) = state.db.org_by_slug(&org_slug)? else {
                continue;
            };
            if let Some(config) = state.db.idp_config(org.id)? {
                if config.enforce_sso {
                    return Ok(Some(org_slug));
                }
            }
        }
    }
    Ok(None)
}

/// The OIDC start path that redirects a browser into an org's IdP login.
///
/// This is the exact target the magic-link path ([`login_submit`]) sends an
/// SSO-enforced user to; the password and passkey paths reuse it so an enforced
/// user lands in the same IdP flow regardless of which credential they tried.
fn sso_start_path(org_slug: &str) -> String {
    format!("/auth/oidc/start?org={}", urlencode(org_slug))
}

/// `POST /login` — route to SSO or issue a magic link.
///
/// Email-first routing (RFC-0004 "domain capture"): when the typed email's
/// domain is captured by an org with an OIDC IdP, the response depends on the
/// org's `enforce_sso`:
///
/// - **enforced** — redirect straight into the OIDC flow (`/auth/oidc/start`);
///   magic links are not offered.
/// - **not enforced** — show a two-step page offering an "Sign in with SSO"
///   button *and* a magic link, keeping the no-JS floor.
///
/// Otherwise a magic link is issued and the "check your email" page shown. The
/// address is never revealed as known/unknown.
///
/// [`LogMailer`]: crate::auth::magic::LogMailer
async fn login_submit(
    State(state): State<Arc<AppState>>,
    crate::server::PeerAddr(peer): crate::server::PeerAddr,
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
    let now = crate::server::now_secs();
    let ip = crate::server::client_ip_for(&headers, peer, state.trusted_proxy);
    use crate::ratelimit::RateClass;
    for (class, key) in [
        (RateClass::MagicLinkEmail, email.as_str()),
        (RateClass::MagicLinkIp, ip.as_str()),
    ] {
        if let crate::ratelimit::RateDecision::Limited { retry_after } =
            state.ratelimit.check(class, key, now)
        {
            return crate::server::too_many_requests(retry_after);
        }
    }
    // Domain capture: route to the org's IdP when one is configured.
    if let Some((org_slug, enforce_sso)) = sso_target(&state, &email) {
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
    let secret = match state.db.create_magic_link(&email) {
        Ok(secret) => secret,
        Err(err) => return internal(err),
    };
    let link = format!(
        "{}/auth/magic?token={secret}",
        state.external_url.trim_end_matches('/'),
    );
    if let Err(err) = state.mailer.send_magic_link(&email, &link) {
        tracing::warn!(error = %format!("{err:#}"), "magic link delivery failed");
    }
    let dev_link = state.dev.then_some(link.as_str());
    Html(console::login_sent_page(&email, dev_link, Instant::now())).into_response()
}

/// `GET /auth/magic?token=` query.
#[derive(serde::Deserialize)]
struct MagicQuery {
    token: String,
}

/// `?page=N` extractor for the paginated console lists (orgs, audit).
#[derive(serde::Deserialize, Default)]
struct PageQuery {
    page: Option<usize>,
}

impl PageQuery {
    /// The requested 1-based page, clamped to at least 1.
    fn page(&self) -> usize {
        self.page.unwrap_or(1).max(1)
    }
}

/// The two independent page parameters of the org dashboard (its registries
/// and members lists paginate separately).
#[derive(serde::Deserialize, Default)]
struct DashboardPages {
    registries_page: Option<usize>,
    members_page: Option<usize>,
}

impl DashboardPages {
    /// The registries list's 1-based page, clamped to at least 1.
    fn registries(&self) -> usize {
        self.registries_page.unwrap_or(1).max(1)
    }

    /// The members list's 1-based page, clamped to at least 1.
    fn members(&self) -> usize {
        self.members_page.unwrap_or(1).max(1)
    }
}

/// `GET /auth/magic?token=<secret>` — consume the link, sign the user in.
///
/// Finds or creates the user by the link's bound email, creates a session,
/// sets the `__Host-` cookie, and redirects to `/`. An unknown, expired, or
/// replayed link returns the login page with an error.
async fn magic_consume(
    State(state): State<Arc<AppState>>,
    Query(query): Query<MagicQuery>,
) -> Response {
    let email = match state.db.consume_magic_link(&query.token) {
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
    let user_id = match state.db.find_or_create_user(&email) {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    // A fresh magic-link sign-in is a re-authentication, so the session is
    // sudo-capable (auth_level 1).
    let cookie = match state.db.create_session(user_id, ABSOLUTE_LIFETIME_SECS, 1) {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
        Err(err) => return internal(err),
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

// -- password login ---------------------------------------------------------

/// `POST /login/password` body: the email and password to authenticate.
#[derive(serde::Deserialize)]
struct PasswordLoginForm {
    email: String,
    password: String,
}

/// `POST /login/password` — authenticate an email + password, sign the user in.
///
/// This is a **pre-auth** endpoint (the caller has no session cookie yet), so
/// it carries no CSRF token — there is no ambient credential to forge against.
/// It *is* rate-limited on both the target email (online password guessing
/// against one account) and the source IP (credential-stuffing sprays),
/// reusing the [`RateClass::PasswordEmail`]/[`RateClass::PasswordIp`] classes.
///
/// On a correct password it creates a sudo-capable session (a fresh password
/// sign-in is a re-authentication, `auth_level 1`), sets the `__Host-` cookie,
/// and redirects to `/`. On *any* failure — unknown email, no password set, or
/// a wrong password — it re-renders `/login` with one generic "invalid email
/// or password" message, never revealing whether the email is registered.
///
/// [`RateClass::PasswordEmail`]: crate::ratelimit::RateClass::PasswordEmail
/// [`RateClass::PasswordIp`]: crate::ratelimit::RateClass::PasswordIp
async fn login_password(
    State(state): State<Arc<AppState>>,
    crate::server::PeerAddr(peer): crate::server::PeerAddr,
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
    let now = crate::server::now_secs();
    let ip = crate::server::client_ip_for(&headers, peer, state.trusted_proxy);
    use crate::ratelimit::RateClass;
    for (class, key) in [
        (RateClass::PasswordEmail, email.as_str()),
        (RateClass::PasswordIp, ip.as_str()),
    ] {
        if let crate::ratelimit::RateDecision::Limited { retry_after } =
            state.ratelimit.check(class, key, now)
        {
            return crate::server::too_many_requests(retry_after);
        }
    }
    let (user_id, hash) = match state.db.user_for_password(&email) {
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
    match sso_enforced_for(&state, &email, Some(user_id)) {
        Ok(Some(org_slug)) => return Redirect::to(&sso_start_path(&org_slug)).into_response(),
        Ok(None) => {}
        Err(err) => return internal(err),
    }
    // A correct password is a re-authentication: the session is sudo-capable.
    let cookie = match state.db.create_session(user_id, ABSOLUTE_LIFETIME_SECS, 1) {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
        Err(err) => return internal(err),
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

// -- OIDC single sign-on ----------------------------------------------------

/// `POST /auth/sso` body: the org to begin an SSO login against.
#[derive(serde::Deserialize)]
struct SsoForm {
    org: String,
}

/// `POST /auth/sso` — the no-JS "Sign in with SSO" button target.
///
/// Reached from the two-step login page when SSO is offered but not enforced;
/// it simply begins the OIDC flow for the named org, mirroring a `GET` of
/// `/auth/oidc/start?org=…`.
async fn login_sso(State(state): State<Arc<AppState>>, Form(form): Form<SsoForm>) -> Response {
    begin_oidc(&state, &form.org, None).await
}

/// `GET /auth/oidc/start?org=` query.
#[derive(serde::Deserialize)]
struct OidcStartQuery {
    org: String,
    #[serde(default)]
    next: Option<String>,
}

/// `GET /auth/oidc/start?org=<slug>` — redirect into the org's IdP.
///
/// Looks up the org and stages the authorization-code + PKCE flow, then
/// 302-redirects the browser to the IdP's authorization endpoint. An unknown
/// org or an org without an IdP renders a clean error page (no stack trace).
async fn oidc_start(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OidcStartQuery>,
) -> Response {
    begin_oidc(&state, &query.org, query.next.as_deref()).await
}

/// Shared "begin OIDC login" helper for the `GET` and `POST` entry points.
async fn begin_oidc(state: &AppState, org_slug: &str, next: Option<&str>) -> Response {
    let org = match state.db.org_by_slug(org_slug) {
        Ok(Some(org)) => org,
        Ok(None) => return sso_error("That organization does not exist."),
        Err(err) => return internal(err),
    };
    match crate::auth::oidc::begin_login(&state.db, &state.external_url, org.id, next) {
        Ok(redirect) => Redirect::to(&redirect.url).into_response(),
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), org = %org_slug, "oidc begin failed");
            sso_error("Single sign-on is not configured for that organization.")
        }
    }
}

/// `GET /auth/oidc/callback?code=&state=` — complete the OIDC login.
///
/// Consumes the staged flow, exchanges the code, verifies the id_token, and on
/// success creates a sudo-capable session and redirects to the flow's
/// `redirect_after` (or `/`). Every failure renders a clean error page rather
/// than leaking internals.
async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<crate::auth::oidc::CallbackParams>,
) -> Response {
    let login = match crate::auth::oidc::complete_login(
        &state.db,
        state.sealer.as_ref(),
        &state.http,
        &state.external_url,
        &params,
    )
    .await
    {
        Ok(login) => login,
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "oidc callback failed");
            return sso_error("Sign-in could not be completed. Please try again.");
        }
    };
    // A fresh SSO sign-in is a re-authentication: the session is sudo-capable.
    let cookie = match state
        .db
        .create_session(login.user_id, ABSOLUTE_LIFETIME_SECS, 1)
    {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
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
fn sso_error(message: &str) -> Response {
    Html(console::login_page(Some(message), None, Instant::now())).into_response()
}

/// `GET /logout` — revoke the caller's own session and clear the cookie.
///
/// A GET logout is acceptable here because it destroys only the caller's own
/// session (no cross-user effect), and clearing one's own cookie is not a
/// state-changing operation worth CSRF-protecting.
async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(secret) = session_secret_from_cookies(&headers) {
        if let Err(err) = state.db.revoke_session(&secret) {
            return internal(err);
        }
    }
    // Expire the cookie by setting Max-Age=0.
    let cleared = format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, cleared)], Redirect::to("/login")).into_response()
}

// -- account ----------------------------------------------------------------

/// `GET /account` — the profile page (email, sessions, tokens, passkeys).
async fn account(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let tokens = match state.db.list_tokens_for(session.principal()) {
        Ok(tokens) => tokens,
        Err(err) => return internal(err),
    };
    let password_set = match state.db.user_has_password(session.auth.user_id) {
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
struct SetPasswordForm {
    #[serde(default)]
    csrf: String,
    password: String,
}

/// `POST /account/password` — set or change the logged-in user's password.
///
/// Session-authed, CSRF-protected, and **sudo-gated** (a fresh
/// re-authentication is required — see [`require_sudo`]): the password is a
/// durable login path, so a stale or stolen ordinary session cannot set it.
/// Hashes the submitted password with Argon2id
/// ([`crate::auth::password::hash_password`]) and stores the PHC string for the
/// session's user.
///
/// On success the change **revokes every session** the user holds (so a stolen
/// sibling session is evicted and a victim recovering their account locks the
/// attacker out), then mints a fresh sudo session for *this* browser and sets
/// the new `__Host-` cookie — the current user stays signed in, everyone else
/// is logged out. An empty or over-long password is rejected with the account
/// page re-rendered (the latter bounds the hashing cost).
async fn account_set_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SetPasswordForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if let Err(resp) = require_sudo(&session) {
        return *resp;
    }
    // A member of an SSO-enforced org must authenticate only through the IdP, so
    // they may not set a durable local password at all — otherwise it would be a
    // standing bypass of IdP deprovisioning / MFA (H-4). Refuse with a `403` and
    // a clear message on the account page.
    match sso_enforced_for(&state, &session.email, Some(session.auth.user_id)) {
        Ok(Some(_)) => {
            let tokens = state
                .db
                .list_tokens_for(session.principal())
                .unwrap_or_default();
            let password_set = state
                .db
                .user_has_password(session.auth.user_id)
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
    // Bound the input: reject empties, and cap the length so a pathological
    // input cannot drive the (memory-hard) hasher into a denial of service.
    if form.password.is_empty() || form.password.len() > 1024 {
        let tokens = state
            .db
            .list_tokens_for(session.principal())
            .unwrap_or_default();
        let password_set = state
            .db
            .user_has_password(session.auth.user_id)
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
    if let Err(err) = state.db.set_user_password(session.auth.user_id, &hash) {
        return internal(err);
    }
    // Evict every session (including this one and any stolen sibling), then
    // re-issue a fresh sudo session for the current browser so the user who
    // just changed their password stays signed in.
    if let Err(err) = state.db.revoke_all_user_sessions(session.auth.user_id) {
        return internal(err);
    }
    let cookie = match state
        .db
        .create_session(session.auth.user_id, ABSOLUTE_LIFETIME_SECS, 1)
    {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
        Err(err) => return internal(err),
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to("/account")).into_response()
}

/// `POST /account/sessions/revoke-all` — sign out of every browser.
async fn account_revoke_all_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if let Err(err) = state.db.revoke_all_user_sessions(session.auth.user_id) {
        return internal(err);
    }
    let cleared = format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, cleared)], Redirect::to("/login")).into_response()
}

/// A form carrying only the CSRF synchronizer token.
#[derive(serde::Deserialize)]
struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

// -- passkeys / WebAuthn ----------------------------------------------------
//
// WebAuthn is the one place the console departs from its no-JS floor: the
// browser's `navigator.credentials` API has no form-only equivalent, so the
// passkey pages serve a small, first-party inline script. The script is gated
// by a per-request CSP nonce (`script-src 'nonce-…'` alongside the global
// `default-src 'self'`), so only that exact `<script nonce=…>` runs — no other
// inline or third-party script is permitted. The script exchanges JSON with the
// begin/finish endpoints, base64url-encoding the binary credential fields.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

/// `GET /account/passkeys` — list the user's passkeys and offer to add one.
///
/// Session-authed. Renders the per-request CSP nonce into both the response
/// header (`script-src 'nonce-…'`) and the inline registration script.
async fn passkeys(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let creds = match state.db.list_user_credentials(session.auth.user_id) {
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
///
/// The CSP keeps the global `default-src 'self'` and adds `script-src 'self'
/// 'nonce-<nonce>'` so the page's single inline script runs while every other
/// inline script stays blocked. The [`security_headers`](crate::server) layer
/// honors this handler-set CSP instead of overwriting it.
fn passkey_html_response(html: String, nonce: &str) -> Response {
    let csp = format!("default-src 'self'; script-src 'self' 'nonce-{nonce}'");
    ([(header::CONTENT_SECURITY_POLICY, csp)], Html(html)).into_response()
}

/// A passkey registration `begin` body: a CSRF token, and the optional label.
#[derive(serde::Deserialize)]
struct PasskeyBeginForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /account/passkeys/begin` — stage a registration challenge (JSON).
///
/// Session-authed and CSRF-protected. Returns the
/// [`RegistrationChallenge`](crate::auth::webauthn::RegistrationChallenge) the
/// inline script feeds to `navigator.credentials.create`.
async fn passkeys_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<PasskeyBeginForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let rp = match crate::auth::webauthn::relying_party(&state.external_url) {
        Ok(rp) => rp,
        Err(err) => return internal(err),
    };
    let rp_name = match crate::ui::render::brand() {
        "" => "Registry Hub",
        brand => brand,
    };
    match crate::auth::webauthn::begin_registration(
        &state.db,
        session.auth.user_id,
        &session.email,
        &rp.id,
        rp_name,
    ) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => internal(err),
    }
}

/// A passkey registration `finish` body, with base64url binary fields.
#[derive(serde::Deserialize)]
struct PasskeyFinishBody {
    csrf: String,
    #[serde(default)]
    label: Option<String>,
    client_data_json: String,
    attestation_object: String,
}

/// `POST /account/passkeys/finish` — verify + persist the new credential.
///
/// Session-authed and CSRF-protected. Decodes the base64url
/// `clientDataJSON`/`attestationObject` the script posts, runs
/// [`finish_registration`](crate::auth::webauthn::finish_registration), and
/// returns `200` with the stored credential id or a `400` with the verifier's
/// reason.
async fn passkeys_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PasskeyFinishBody>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &body.csrf) {
        return *resp;
    }
    // A passkey is a local credential. A member of an SSO-enforced org must not
    // enroll one, just as they may not set a password (H-4) — both would bypass
    // IdP deprovisioning. Refuse enrollment with a `403`.
    match sso_enforced_for(&state, &session.email, Some(session.auth.user_id)) {
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
    let rp = match crate::auth::webauthn::relying_party(&state.external_url) {
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
        &state.db,
        session.auth.user_id,
        &rp.id,
        &rp.origin,
        &response,
        label,
    ) {
        Ok(credential_id) => {
            Json(serde_json::json!({ "credential_id": credential_id })).into_response()
        }
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "passkey registration rejected");
            (StatusCode::BAD_REQUEST, "passkey registration failed").into_response()
        }
    }
}

/// `POST /auth/passkey/begin` — stage a usernameless assertion challenge (JSON).
///
/// Pre-auth (the login path). Returns the
/// [`AssertionChallenge`](crate::auth::webauthn::AssertionChallenge) the inline
/// login script feeds to `navigator.credentials.get`.
async fn passkey_login_begin(
    State(state): State<Arc<AppState>>,
    crate::server::PeerAddr(peer): crate::server::PeerAddr,
    headers: HeaderMap,
) -> Response {
    // Rate-limit assertion-challenge issuance per source IP, the same pre-auth
    // spray bound as magic-link issuance.
    let now = crate::server::now_secs();
    let ip = crate::server::client_ip_for(&headers, peer, state.trusted_proxy);
    if let crate::ratelimit::RateDecision::Limited { retry_after } =
        state
            .ratelimit
            .check(crate::ratelimit::RateClass::MagicLinkIp, &ip, now)
    {
        return crate::server::too_many_requests(retry_after);
    }
    let rp = match crate::auth::webauthn::relying_party(&state.external_url) {
        Ok(rp) => rp,
        Err(err) => return internal(err),
    };
    match crate::auth::webauthn::begin_assertion(&state.db, &rp.id) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => internal(err),
    }
}

/// A passkey login `finish` body, with base64url binary fields.
#[derive(serde::Deserialize)]
struct PasskeyLoginBody {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

/// `POST /auth/passkey/finish` — verify the assertion, sign the user in.
///
/// Pre-auth. On success, creates a sudo-capable session
/// ([`Database::create_session`](crate::db::Database::create_session) with
/// `auth_level = 1` — a passkey assertion is a fresh re-authentication), sets
/// the `__Host-` cookie, and returns `200` so the script can redirect. A failed
/// assertion is a `401` with no cookie.
async fn passkey_login_finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasskeyLoginBody>,
) -> Response {
    let rp = match crate::auth::webauthn::relying_party(&state.external_url) {
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
        match crate::auth::webauthn::finish_assertion(&state.db, &rp.id, &rp.origin, &response) {
            Ok(id) => id,
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "passkey assertion rejected");
                return (StatusCode::UNAUTHORIZED, "passkey sign-in failed").into_response();
            }
        };
    // A passkey is a local credential: like a password, it must not let a user
    // subject to `enforce_sso` bypass the IdP (H-4). The assertion verified, so
    // we know which user it is; if any of their orgs enforces SSO, refuse to
    // mint the local session and steer the login script to the IdP instead.
    match state.db.user_email(user_id) {
        Ok(Some(email)) => match sso_enforced_for(&state, &email, Some(user_id)) {
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
        // No email row (a deleted user) — fall through to the normal failure.
        Ok(None) => return (StatusCode::UNAUTHORIZED, "passkey sign-in failed").into_response(),
        Err(err) => return internal(err),
    }
    let cookie = match state.db.create_session(user_id, ABSOLUTE_LIFETIME_SECS, 1) {
        Ok(secret) => set_cookie_header(&secret, ABSOLUTE_LIFETIME_SECS),
        Err(err) => return internal(err),
    };
    (
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "ok": true })),
    )
        .into_response()
}

// -- device approval (RFC 8628) ---------------------------------------------

/// `GET /activate?user_code=` query.
#[derive(Default, serde::Deserialize)]
struct ActivateQuery {
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
/// keyed on the **session user combined with the client IP**, so neither a
/// single account nor a single source can spin the wheel quickly, and returns
/// `Some(429)` (with `Retry-After`) when the budget is exhausted. Both the GET
/// form and the POST submit call it. (The future polling endpoint, when wired,
/// should meter the same class on the requesting CLI principal.)
fn activate_rate_limited(
    state: &AppState,
    session: &Session,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> Option<Response> {
    let ip = crate::server::client_ip_for(headers, peer, state.trusted_proxy);
    let key = format!("{}|{ip}", session.auth.user_id);
    match state.ratelimit.check(
        crate::ratelimit::RateClass::DeviceActivate,
        &key,
        crate::server::now_secs(),
    ) {
        crate::ratelimit::RateDecision::Limited { retry_after } => {
            Some(crate::server::too_many_requests(retry_after))
        }
        crate::ratelimit::RateDecision::Allowed => None,
    }
}

/// `GET /activate` — the device-approval page.
///
/// Prefills the user code from `?user_code=` and, when it resolves to a live
/// pending grant, shows the requested scope/permissions and the approve form.
async fn activate_form(
    State(state): State<Arc<AppState>>,
    crate::server::PeerAddr(peer): crate::server::PeerAddr,
    headers: HeaderMap,
    Query(query): Query<ActivateQuery>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Some(resp) = activate_rate_limited(&state, &session, &headers, peer) {
        return resp;
    }
    let user_code = query.user_code.unwrap_or_default();
    let request = if user_code.is_empty() {
        None
    } else {
        match state.db.pending_device_request(&user_code) {
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
        Instant::now(),
    ))
    .into_response()
}

/// `POST /activate` form: the user code and the approve/deny decision.
#[derive(serde::Deserialize)]
struct ActivateForm {
    #[serde(default)]
    csrf: String,
    user_code: String,
    decision: String,
}

/// `POST /activate` — approve or deny a device grant.
///
/// Approval clamps the minted token to the approver's current grants (the
/// clamp lives in [`crate::db::Database::approve_device`]); denial marks the
/// grant denied. Redirects back to `/activate` with a result message.
async fn activate_submit(
    State(state): State<Arc<AppState>>,
    crate::server::PeerAddr(peer): crate::server::PeerAddr,
    headers: HeaderMap,
    Form(form): Form<ActivateForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Some(resp) = activate_rate_limited(&state, &session, &headers, peer) {
        return resp;
    }
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let message = if form.decision == "approve" {
        let grants = match session.grants(&state.db) {
            Ok(grants) => grants,
            Err(err) => return internal(err),
        };
        match state
            .db
            .approve_device(&form.user_code, session.principal(), &grants)
        {
            Ok(true) => "Approved. Return to your terminal — the CLI will continue.",
            Ok(false) => "That code is unknown, already resolved, or expired.",
            Err(err) => return internal(err),
        }
    } else {
        match state.db.deny_device(&form.user_code) {
            Ok(_) => "Denied.",
            Err(err) => return internal(err),
        }
    };
    Redirect::to(&format!("/activate?message={}", urlencode(message))).into_response()
}

// -- orgs -------------------------------------------------------------------

/// `GET /-/orgs` — the user's org list.
async fn orgs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PageQuery>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let result = (|| {
        let grants = session.grants(&state.db)?;
        let mut orgs = Vec::new();
        for org in state.db.list_orgs()? {
            // Show an org if the user has any read grant covering it.
            if iam::allow(&grants, Permission::Read, &Scope::parse(&org.slug)) {
                orgs.push(org);
            }
        }
        let can_create = may_create_org(&state.db, &session)?;
        // An instance admin (iam.admin at the root scope) sees the
        // instance-settings link.
        let is_instance_admin = iam::allow(&grants, Permission::IamAdmin, &Scope::parse(""));
        Ok::<_, anyhow::Error>((orgs, can_create, is_instance_admin))
    })();
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

/// Whether the instance signup policy permits `session`'s user to create an
/// org — the web equivalent of [`crate::rpc`]'s `signup_permitted`.
///
/// Under [`crate::db::SignupPolicy::Open`] any signed-in user may create one.
/// Under `InviteOnly`, the user must already be a member of some org, hold a
/// live invitation for their email, or be an instance admin (an `iam.admin`
/// grant at the instance root).
///
/// # Errors
///
/// Returns an error on database failure.
fn may_create_org(db: &Database, session: &Session) -> anyhow::Result<bool> {
    if db.signup_policy()? == crate::db::SignupPolicy::Open {
        return Ok(true);
    }
    let user_id = session.auth.user_id;
    if db.user_has_any_membership(user_id)? {
        return Ok(true);
    }
    let grants = session.grants(db)?;
    if iam::allow(&grants, Permission::IamAdmin, &Scope::root()) {
        return Ok(true);
    }
    if db.has_pending_invitation(&session.email)? {
        return Ok(true);
    }
    Ok(false)
}

/// `GET /-/org/{org}` — the org dashboard.
async fn org_dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Query(pages): Query<DashboardPages>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = Scope::parse(&org_slug);
    // A non-member must not learn the org exists: 404 a private dashboard.
    if !session.allows(&state.db, Permission::Read, &scope) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            return Ok(None);
        };
        let projects = state.db.list_projects(org.id)?;
        let bindings = state.db.list_storage_bindings(org.id)?;
        let registries: Vec<RegistryRecord> = state
            .db
            .list_registries()?
            .into_iter()
            .filter(|r| r.org_id == Some(org.id))
            .collect();
        let members = load_members(&state.db, &org_slug)?;
        let owner_count = members.iter().filter(|m| m.role == "owner").count();
        let can_manage = session.allows(&state.db, Permission::MembersManage, &scope);
        let can_audit = session.allows(&state.db, Permission::AuditRead, &scope);
        // RegistryConfigure gates project/registry creation; StorageManage gates
        // binding creation. Both belong to admin+, so a single "can configure"
        // flag drives every create affordance on the dashboard.
        let can_configure = session.allows(&state.db, Permission::RegistryConfigure, &scope);
        // Org deletion is owner-only (it needs the owner-exclusive iam.admin).
        let can_delete = session.allows(&state.db, Permission::IamAdmin, &scope);
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
    })();
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Load an org's direct members as console rows (resolving user emails).
fn load_members(db: &Database, org_slug: &str) -> anyhow::Result<Vec<console::MemberRow>> {
    let mut rows = Vec::new();
    for (kind, id, role) in db.list_members_of_scope(org_slug)? {
        let label = if kind == "user" {
            db.user_email(id)?.unwrap_or_else(|| format!("user:{id}"))
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
async fn org_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Query(params): Query<PageQuery>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = Scope::parse(&org_slug);
    if !session.allows(&state.db, Permission::AuditRead, &scope) {
        // A member without audit.read gets 403 (the org is known to them);
        // a non-member gets 404 (existence undisclosed).
        if session.allows(&state.db, Permission::Read, &scope) {
            return (StatusCode::FORBIDDEN, "audit read requires admin").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            return Ok(None);
        };
        let rows = state.db.list_audit(&org_slug)?;
        Ok::<_, anyhow::Error>(Some(console::audit_page(
            &session.email,
            &org,
            &rows,
            params.page(),
            Instant::now(),
        )))
    })();
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// Why a membership grant or role change was refused by a console handler.
///
/// Each variant maps to a distinct HTTP status so the caller sees the right
/// failure: a privilege-ceiling violation is a `403`, the last-owner guard a
/// `409`.
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
/// Returns `Ok(Err(_))` with a [`MembershipReject::Forbidden`] when `actor`
/// would grant `role` to `target` at `scope` beyond its own authority — the
/// same rule the central guard enforces, surfaced here so the console returns
/// a precise `403` rather than a generic `500`. Returns `Ok(Ok(()))` when the
/// grant is within the actor's authority.
///
/// # Errors
///
/// Returns an error on database failure.
fn membership_grant_allowed(
    db: &Database,
    actor: &Principal,
    target: &Principal,
    scope: &Scope,
    role: Role,
) -> anyhow::Result<Result<(), MembershipReject>> {
    let actor_rank = db
        .effective_scopes(*actor)?
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
struct InviteForm {
    #[serde(default)]
    csrf: String,
    email: String,
    role: String,
}

/// `POST /-/org/{org}/members` — invite a member through a change-set.
///
/// Requires `MembersManage` at the org scope. Creating the invitation flows
/// through the change-set engine so it audits.
async fn org_invite_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<InviteForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    // Inviting a member changes who is trusted in the org, so it gates on
    // sudo (M-1).
    if let Err(resp) = require_sudo(&session) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session.allows(&state.db, Permission::MembersManage, &scope) {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    let Some(role) = Role::parse(&form.role) else {
        return (StatusCode::BAD_REQUEST, "unknown role").into_response();
    };
    let email = form.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return (StatusCode::BAD_REQUEST, "invalid email").into_response();
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            anyhow::bail!("no org");
        };
        // Record the invitation as a change-set so it audits, then create the
        // pending invitation row.
        let invitee = state.db.find_or_create_user(&email)?;
        let target = Principal::user(invitee);
        // Refuse an invitation at a role above the actor's own authority (H1).
        if let Err(reject) =
            membership_grant_allowed(&state.db, &session.principal(), &target, &scope, role)?
        {
            return Ok(Err(reject));
        }
        config::change_membership(
            &state.db,
            &session.principal(),
            &session.email,
            MembershipChange::Grant,
            &target,
            &scope,
            role,
        )?;
        let _ = org; // org id reserved for an invitation-table write later.
        Ok::<Result<(), MembershipReject>, anyhow::Error>(Ok(()))
    })();
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(Err(reject)) => reject.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/members/remove` form.
#[derive(serde::Deserialize)]
struct RemoveForm {
    #[serde(default)]
    csrf: String,
    principal_kind: String,
    principal_id: i64,
}

/// `POST /-/org/{org}/members/remove` — revoke a member through a change-set.
///
/// Requires `MembersManage`. The last org owner cannot be removed (hard
/// block). The revoke flows through the change-set engine so it audits.
async fn org_remove_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<RemoveForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session.allows(&state.db, Permission::MembersManage, &scope) {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    // Revoking a membership changes who is trusted in the org, so it gates on
    // sudo (M-1).
    if let Err(resp) = require_sudo(&session) {
        return *resp;
    }
    let Some(kind) = crate::domain::PrincipalKind::parse(&form.principal_kind) else {
        return (StatusCode::BAD_REQUEST, "unknown principal kind").into_response();
    };
    let result = (|| {
        // Hard-block removing the last owner.
        let members = state.db.list_members_of_scope(&org_slug)?;
        let owners: Vec<_> = members.iter().filter(|(_, _, r)| r == "owner").collect();
        let target_is_owner = members.iter().any(|(k, id, r)| {
            k == &form.principal_kind && *id == form.principal_id && r == "owner"
        });
        if target_is_owner && owners.len() <= 1 {
            return Ok(Err(()));
        }
        config::change_membership(
            &state.db,
            &session.principal(),
            &session.email,
            MembershipChange::Revoke,
            &Principal {
                kind,
                id: form.principal_id,
            },
            &scope,
            Role::Viewer,
        )?;
        Ok::<Result<(), ()>, anyhow::Error>(Ok(()))
    })();
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(Err(())) => (
            StatusCode::CONFLICT,
            "cannot remove the last owner of an organization",
        )
            .into_response(),
        // The transactional owner-guard in the write path is the real defense
        // against the concurrent-demote race; surface its rollback as the same
        // 409 the pre-check renders, never a generic 500.
        Err(err) if crate::db::is_last_owner_error(&err) => (
            StatusCode::CONFLICT,
            "cannot remove the last owner of an organization",
        )
            .into_response(),
        Err(err) => internal(err),
    }
}

// -- create organization ----------------------------------------------------

/// `GET /new` — the create-organization form.
///
/// Session-authed and signup-gated: a user the instance signup policy forbids
/// from creating an org (invite-only, and not a member/invitee/admin) gets the
/// form replaced by an explanatory `403`, mirroring [`crate::rpc`]'s
/// `CreateOrg` policy.
async fn new_org_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    match may_create_org(&state.db, &session) {
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
struct NewOrgForm {
    #[serde(default)]
    csrf: String,
    slug: String,
    name: String,
}

/// `POST /new` — create an org and auto-grant the caller `Owner`.
///
/// CSRF-checked and signup-gated (the same policy as [`new_org_form`] and the
/// `CreateOrg` RPC). On success the caller becomes the org's first owner (the
/// web equivalent of the RPC auto-grant), the creation is audited, and the
/// browser is redirected to the new org's dashboard. A bad/taken slug
/// re-renders the form with an inline error.
async fn new_org_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<NewOrgForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    match may_create_org(&state.db, &session) {
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
    // The slug becomes a scope segment and a URL path, so constrain it to the
    // shared canonical single-segment charset (no slashes, spaces, control,
    // or uppercase chars, and not a reserved name) — the same ruleset the
    // CLI and Connect RPC enforce, so the surfaces never drift (sec CR-2).
    if let Err(err) = iam::validate_org_slug(slug) {
        return reject(&format!(
            "The slug may contain only lowercase letters, digits, '-', and '_', and must not be a reserved name ({err})."
        ));
    }
    let result = (|| {
        if state.db.org_by_slug_including_deleted(slug)?.is_some() {
            return Ok(Err("That slug is already taken."));
        }
        state.db.create_org(slug, name)?;
        // Auto-grant the creator Owner (mirrors CreateOrg's bootstrap grant).
        state
            .db
            .grant_membership("user", session.auth.user_id, slug, Role::Owner.as_str())?;
        state.db.record_audit(
            "user",
            Some(session.auth.user_id),
            &session.email,
            "org.create",
            slug,
            None,
            None,
            None,
            Some(name),
        )?;
        Ok::<Result<(), &str>, anyhow::Error>(Ok(()))
    })();
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{slug}")).into_response(),
        Ok(Err(message)) => reject(message),
        Err(err) => internal(err),
    }
}

// -- create project / binding / registry under an org -----------------------

/// `POST /-/org/{org}/projects` form: a materialized path and a display name.
#[derive(serde::Deserialize)]
struct NewProjectForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    path: String,
    name: String,
}

/// `POST /-/org/{org}/projects` — create a project under an org.
///
/// CSRF-checked and `RegistryConfigure`-gated at the org scope (matching the
/// `CreateProject` RPC). Audited, then redirects to the org dashboard.
async fn org_create_project(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<NewProjectForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&state, &session, &scope, Permission::RegistryConfigure) {
        return *deny;
    }
    let name = form.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "project name is required").into_response();
    }
    let path = form.path.trim().trim_matches('/');
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            return Ok(false);
        };
        state.db.create_project(org.id, path, name)?;
        state.db.record_audit(
            "user",
            Some(session.auth.user_id),
            &session.email,
            "project.create",
            &org_slug,
            None,
            None,
            None,
            Some(name),
        )?;
        Ok::<_, anyhow::Error>(true)
    })();
    match result {
        Ok(true) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        // A duplicate (org, path) is an operator error, not a fault.
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

/// `POST /-/org/{org}/projects/delete` / `bindings/delete` form: a row id.
#[derive(serde::Deserialize)]
struct DeleteByIdForm {
    #[serde(default)]
    csrf: String,
    id: i64,
}

/// `POST /-/org/{org}/projects/delete` — delete an empty project.
///
/// `RegistryConfigure`-gated and CSRF-checked. Refuses to delete a project that
/// still has registries nested under its path (an in-use guard), so removal
/// never orphans a registry.
async fn org_delete_project(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<DeleteByIdForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&state, &session, &scope, Permission::RegistryConfigure) {
        return *deny;
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            return Ok(None);
        };
        let Some(project) = state
            .db
            .list_projects(org.id)?
            .into_iter()
            .find(|p| p.id == form.id)
        else {
            return Ok(Some(Err("no such project")));
        };
        // In-use guard: a registry nested under this project blocks removal.
        let in_use = state
            .db
            .list_registries()?
            .into_iter()
            .any(|r| r.org_id == Some(org.id) && r.project_path == project.path);
        if in_use {
            return Ok(Some(Err("project still has registries")));
        }
        state.db.delete_project(org.id, project.id)?;
        state.db.record_audit(
            "user",
            Some(session.auth.user_id),
            &session.email,
            "project.delete",
            &org_slug,
            None,
            None,
            None,
            Some(&project.path),
        )?;
        Ok::<_, anyhow::Error>(Some(Ok(())))
    })();
    match result {
        Ok(Some(Ok(()))) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(Some(Err(msg))) => (StatusCode::CONFLICT, msg).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/bindings/delete` — delete an unused storage binding.
///
/// `StorageManage`-gated and CSRF-checked. Refuses to delete a binding any
/// registry still uses (an in-use guard).
async fn org_delete_binding(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<DeleteByIdForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&state, &session, &scope, Permission::StorageManage) {
        return *deny;
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            return Ok(None);
        };
        let Some(binding) = state
            .db
            .list_storage_bindings(org.id)?
            .into_iter()
            .find(|b| b.id == form.id)
        else {
            return Ok(Some(Err("no such binding")));
        };
        let in_use = state
            .db
            .list_registries()?
            .into_iter()
            .any(|r| r.storage_binding_id == Some(binding.id));
        if in_use {
            return Ok(Some(Err("binding still in use by a registry")));
        }
        state.db.delete_storage_binding(org.id, binding.id)?;
        state.db.record_audit(
            "user",
            Some(session.auth.user_id),
            &session.email,
            "binding.delete",
            &org_slug,
            None,
            None,
            None,
            Some(&binding.name),
        )?;
        Ok::<_, anyhow::Error>(Some(Ok(())))
    })();
    match result {
        Ok(Some(Ok(()))) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(Some(Err(msg))) => (StatusCode::CONFLICT, msg).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/members/role` form: a principal and its new role.
#[derive(serde::Deserialize)]
struct RoleForm {
    #[serde(default)]
    csrf: String,
    principal_kind: String,
    principal_id: i64,
    role: String,
}

/// `POST /-/org/{org}/members/role` — change a member's role.
///
/// `MembersManage`-gated and CSRF-checked. Re-grants the membership at the new
/// role (an audited change-set). Demoting the last owner is blocked so an org
/// can never be left ownerless.
async fn org_member_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<RoleForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session.allows(&state.db, Permission::MembersManage, &scope) {
        return (StatusCode::FORBIDDEN, "members.manage required").into_response();
    }
    // Changing a member's role changes who/what is trusted in the org, so it
    // gates on sudo (M-1).
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
    let result = (|| {
        // Refuse a grant that exceeds the actor's own authority (H1).
        if let Err(reject) =
            membership_grant_allowed(&state.db, &session.principal(), &target, &scope, role)?
        {
            return Ok(Err(reject));
        }
        // Block demoting the last owner away from `owner`.
        let members = state.db.list_members_of_scope(&org_slug)?;
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
            &state.db,
            &session.principal(),
            &session.email,
            MembershipChange::Grant,
            &target,
            &scope,
            role,
        )?;
        Ok::<Result<(), MembershipReject>, anyhow::Error>(Ok(()))
    })();
    match result {
        Ok(Ok(())) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(Err(reject)) => reject.into_response(),
        // The transactional owner-guard in the write path is the real defense
        // against the concurrent-demote race; surface its rollback as the same
        // 409 the `MembershipReject::LastOwner` pre-check renders.
        Err(err) if crate::db::is_last_owner_error(&err) => {
            MembershipReject::LastOwner.into_response()
        }
        Err(err) => internal(err),
    }
}

/// `GET /-/instance` — the instance-settings page (instance admins only).
async fn instance_settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_instance_settings(&state, &session, None)
}

/// Render the instance-settings page; instance-admin (`iam.admin` at the root
/// scope) only.
fn render_instance_settings(state: &AppState, session: &Session, notice: Option<&str>) -> Response {
    if !session.allows(&state.db, Permission::IamAdmin, &Scope::parse("")) {
        return (StatusCode::FORBIDDEN, "instance admin required").into_response();
    }
    let policy = match state.db.signup_policy() {
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
struct InstanceSettingsForm {
    #[serde(default)]
    csrf: String,
    signup_policy: String,
}

/// `POST /-/instance` — update the instance signup policy (instance admins).
async fn instance_settings_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<InstanceSettingsForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    if !session.allows(&state.db, Permission::IamAdmin, &Scope::parse("")) {
        return (StatusCode::FORBIDDEN, "instance admin required").into_response();
    }
    let policy = crate::db::SignupPolicy::parse(&form.signup_policy);
    if let Err(err) = state.db.set_signup_policy(policy) {
        return internal(err);
    }
    if let Err(err) = state.db.record_audit(
        "user",
        Some(session.auth.user_id),
        &session.email,
        "instance.signup_policy",
        "",
        None,
        None,
        None,
        Some(policy.as_str()),
    ) {
        return internal(err);
    }
    render_instance_settings(&state, &session, Some("Signup policy saved."))
}

/// `POST /-/org/{org}/bindings` form: a name and an absolute root path.
#[derive(serde::Deserialize)]
struct NewBindingForm {
    #[serde(default)]
    csrf: String,
    name: String,
    root: String,
}

/// `POST /-/org/{org}/bindings` — create a `local_fs` storage binding.
///
/// CSRF-checked and `StorageManage`-gated at the org scope. The root must be an
/// absolute path with no `..` components (a binding root relocates a whole
/// surface tree, so it is validated up front). Audited, then redirects to the
/// dashboard.
async fn org_create_binding(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<NewBindingForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&state, &session, &scope, Permission::StorageManage) {
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
    // The root must be an absolute path with no traversal components.
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
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            return Ok(false);
        };
        state
            .db
            .create_storage_binding(org.id, name, "local_fs", root)?;
        state.db.record_audit(
            "user",
            Some(session.auth.user_id),
            &session.email,
            "binding.create",
            &org_slug,
            None,
            None,
            None,
            Some(name),
        )?;
        Ok::<_, anyhow::Error>(true)
    })();
    match result {
        Ok(true) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

/// `GET /-/org/{org}/registries/new` — the create-registry form.
///
/// `RegistryConfigure`-gated at the org scope (a member without it gets `403`,
/// a non-member `404`). Renders the project/binding selects from the org's
/// current projects and bindings; with no bindings the form prompts to create
/// one first.
async fn org_new_registry_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&state, &session, &scope, Permission::RegistryConfigure) {
        return *deny;
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            return Ok(None);
        };
        let projects = state.db.list_projects(org.id)?;
        let bindings = state.db.list_storage_bindings(org.id)?;
        Ok::<_, anyhow::Error>(Some(console::new_registry_page(
            &session.email,
            &org,
            &session.csrf(),
            &projects,
            &bindings,
            None,
            Instant::now(),
        )))
    })();
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/registries` form: the new managed registry's fields.
#[derive(serde::Deserialize)]
struct NewRegistryForm {
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
///
/// CSRF-checked and `RegistryConfigure`-gated at the org scope (mirroring the
/// `CreateRegistry` RPC). Resolves the chosen binding by name, parses the
/// trust-anchor textarea (one `name:Ed25519:<base64>` line each), creates the
/// registry, audits it, and redirects to the new registry's home. A
/// duplicate canonical path or bad binding re-renders the form with an inline
/// error.
async fn org_create_registry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<NewRegistryForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if let Some(deny) = require_org_perm(&state, &session, &scope, Permission::RegistryConfigure) {
        return *deny;
    }
    let Some(org) = (match state.db.org_by_slug(&org_slug) {
        Ok(org) => org,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let reject = |state: &AppState, message: &str| {
        let projects = state.db.list_projects(org.id).unwrap_or_default();
        let bindings = state.db.list_storage_bindings(org.id).unwrap_or_default();
        Html(console::new_registry_page(
            &session.email,
            &org,
            &session.csrf(),
            &projects,
            &bindings,
            Some(message),
            Instant::now(),
        ))
        .into_response()
    };

    let name = form.name.trim();
    if name.is_empty() {
        return reject(&state, "Registry name is required.");
    }
    let visibility = match form.visibility.trim() {
        "" => "private",
        v @ ("public" | "internal" | "private") => v,
        _ => return reject(&state, "Invalid visibility."),
    };
    // Resolve the storage binding by name within the org.
    let binding_id = match state
        .db
        .storage_binding_by_name(org.id, form.binding.trim())
    {
        Ok(Some(b)) => b.id,
        Ok(None) => return reject(&state, "Choose a storage binding."),
        Err(err) => return internal(err),
    };
    let project_path = form.project_path.trim().trim_matches('/');
    let prefix = form.prefix.trim();
    // One trust anchor per non-empty line.
    let trust_keys: Vec<String> = form
        .trust_keys
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let require_signatures = form.require_signatures.is_some();

    let created = state.db.create_managed_registry(
        org.id,
        project_path,
        name,
        visibility,
        Some(binding_id),
        prefix,
        &trust_keys,
        require_signatures,
    );
    match created {
        Ok(_) => {}
        Err(err) => return reject(&state, &format!("{err:#}")),
    }
    let canonical = match state.db.registry_by_scope(&org.slug, project_path, name) {
        Ok(Some(reg)) => reg.slug,
        Ok(None) => return internal(anyhow::anyhow!("registry vanished after creation")),
        Err(err) => return internal(err),
    };
    if let Err(err) = state.db.record_audit(
        "user",
        Some(session.auth.user_id),
        &session.email,
        "registry.create",
        &canonical,
        None,
        None,
        None,
        Some(visibility),
    ) {
        return internal(err);
    }
    Redirect::to(&format!("/{canonical}/")).into_response()
}

/// `POST /-/org/{org}/delete` form: the typed-confirmation slug.
#[derive(serde::Deserialize)]
struct OrgDeleteForm {
    #[serde(default)]
    csrf: String,
    confirm: String,
}

/// Soft-delete grace window: 30 days (matches the offboarding default).
const ORG_DELETE_GRACE_SECS: i64 = 30 * 24 * 60 * 60;

/// `POST /-/org/{org}/delete` — soft-delete an org behind a typed confirmation.
///
/// Owner-only (`IamAdmin` at the org scope), CSRF-checked, and **sudo-gated**
/// (a fresh re-authentication — see [`require_sudo`]). The `confirm`
/// field must exactly equal the org slug. Calls the existing
/// [`crate::db::Database::soft_delete_org`] (a 30-day grace window), audits the
/// deletion, and redirects to `/-/orgs`.
async fn org_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<OrgDeleteForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
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
    if let Some(deny) = require_org_perm(&state, &session, &scope, Permission::IamAdmin) {
        return *deny;
    }
    if form.confirm.trim() != org_slug {
        return (
            StatusCode::BAD_REQUEST,
            "type the organization slug to confirm",
        )
            .into_response();
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(&org_slug)? else {
            return Ok(false);
        };
        let deleted = state.db.soft_delete_org(org.id, ORG_DELETE_GRACE_SECS)?;
        if deleted {
            state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "org.delete",
                &org_slug,
                None,
                None,
                None,
                None,
            )?;
        }
        Ok::<_, anyhow::Error>(deleted)
    })();
    match result {
        Ok(_) => Redirect::to("/-/orgs").into_response(),
        Err(err) => internal(err),
    }
}

/// Gate a mutation on `perm` at an org `scope`: `403` for a member who lacks
/// it, `404` for a non-member (existence undisclosed), `None` when allowed.
///
/// The shared authz shape for the org-scoped create/delete handlers, matching
/// the `404`-private / `403`-forbidden discipline the read pages use.
fn require_org_perm(
    state: &AppState,
    session: &Session,
    scope: &Scope,
    perm: Permission,
) -> Option<Box<Response>> {
    if session.allows(&state.db, perm, scope) {
        return None;
    }
    if session.allows(&state.db, Permission::Read, scope) {
        Some(Box::new(
            (StatusCode::FORBIDDEN, "insufficient permission").into_response(),
        ))
    } else {
        Some(Box::new(StatusCode::NOT_FOUND.into_response()))
    }
}

// -- registry settings / management landing ---------------------------------

/// `GET /{slug}/-/settings` — the registry management landing page.
async fn registry_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    registry_settings_view(&state, &session, &registry, None)
}

/// Render the registry settings landing page, optionally echoing a
/// just-applied visibility change-set id.
///
/// `RegistryConfigure`-gated: a member without it gets `403`, a non-member of a
/// private registry's org gets `404`.
fn registry_settings_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<&str>,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) = require_org_perm(state, session, &scope, Permission::RegistryConfigure) {
        return *deny;
    }
    let result_outcome = (|| {
        // Resolve the storage binding (name, root, prefix) when bound.
        let binding = match registry.storage_binding_id {
            Some(id) => state
                .db
                .storage_binding(id)?
                .map(|b| (b.name, b.root, registry.prefix.clone())),
            None => None,
        };
        // Deletion is owner-only (the iam.admin verb).
        let can_delete = session.allows(&state.db, Permission::IamAdmin, &scope);
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
    })();
    match result_outcome {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /{slug}/-/settings/visibility` form: the new visibility.
#[derive(serde::Deserialize)]
struct VisibilityForm {
    #[serde(default)]
    csrf: String,
    visibility: String,
}

/// `POST /{slug}/-/settings/visibility` — change a registry's visibility.
async fn registry_visibility(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<VisibilityForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    registry_visibility_action(&state, &session, &registry, &form.csrf, &form.visibility)
}

/// The visibility-change action: CSRF + `RegistryConfigure` gate, then route
/// the flip through the audited change-set engine and re-render the settings
/// page with the new change id.
fn registry_visibility_action(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    visibility: &str,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) = require_org_perm(state, session, &scope, Permission::RegistryConfigure) {
        return *deny;
    }
    let visibility = match visibility.trim() {
        v @ ("public" | "internal" | "private") => v,
        _ => return (StatusCode::BAD_REQUEST, "invalid visibility").into_response(),
    };
    let change_id = match config::change_registry_visibility(
        &state.db,
        &session.principal(),
        &session.email,
        registry.id,
        visibility,
    ) {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    // Re-read so the page shows the new visibility.
    let updated = match state.db.registry_by_slug(&registry.slug) {
        Ok(Some(reg)) => reg,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    registry_settings_view(state, session, &updated, Some(change_id.0.as_str()))
}

/// `POST /{slug}/-/settings/delete` form: the typed-confirmation name.
#[derive(serde::Deserialize)]
struct RegistryDeleteForm {
    #[serde(default)]
    csrf: String,
    confirm: String,
}

/// `POST /{slug}/-/settings/delete` — unregister a registry.
async fn registry_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<RegistryDeleteForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    registry_delete_action(&state, &session, &registry, &form.csrf, &form.confirm)
}

/// The registry-delete action: CSRF + sudo + owner/admin (`IamAdmin`) gate and
/// a typed-confirmation match on the registry slug, then remove the row.
///
/// Deletion requires a sudo session (a fresh re-authentication — see
/// [`require_sudo`]) in addition to the authorization check below.
/// Deletion is owner/admin-level: it requires `IamAdmin` at the registry's
/// canonical scope (an org owner holds it everywhere beneath the org). The
/// `confirm` field must exactly equal the registry slug. Removes the
/// `registries` row (cascading its rebuildable index; surface content on the
/// binding is left in place), audits it, and redirects to the owning org's
/// dashboard (or `/` for an unowned registry).
fn registry_delete_action(
    state: &AppState,
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
    if let Some(deny) = require_org_perm(state, session, &scope, Permission::IamAdmin) {
        return *deny;
    }
    if confirm.trim() != registry.slug {
        return (StatusCode::BAD_REQUEST, "type the registry name to confirm").into_response();
    }
    let result = (|| {
        let removed = state.db.delete_registry(registry.id)?;
        if removed {
            state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "registry.delete",
                &registry.slug,
                None,
                None,
                None,
                None,
            )?;
        }
        // Redirect to the owning org's dashboard when known.
        let target = match registry.org_id {
            Some(org_id) => match state.db.org_by_id(org_id)? {
                Some(org) => format!("/-/org/{}", org.slug),
                None => "/".to_string(),
            },
            None => "/".to_string(),
        };
        Ok::<_, anyhow::Error>(target)
    })();
    match result {
        Ok(target) => Redirect::to(&target).into_response(),
        Err(err) => internal(err),
    }
}

/// Whether the `/-/` tail `right` (with the given method) names a
/// producer-console page, as opposed to a consumer browse page.
///
/// Returns `false` for browse pages (`packages`, `channels/{name}`,
/// `releases`, `health`, …) so [`dispatch_nested`] leaves them to the
/// browse resolver and never bounces an anonymous reader to `/login`.
fn is_console_path(right: &str, is_post: bool) -> bool {
    match right {
        "settings/tokens" => true,
        "settings/tokens/revoke" | "settings/tokens/rotate" => is_post,
        // The config-edit page is GET (form) + POST (submit); the change-request
        // list is GET-only.
        "settings/config" => true,
        // The settings landing page is GET-only; visibility and delete are
        // POST-only mutations.
        "settings" => !is_post,
        "settings/visibility" | "settings/delete" => is_post,
        // The serving & mirror page is GET (view) + POST (mutate).
        "settings/serving" => true,
        "changes" => !is_post,
        "keys" | "keys/rotate" | "publishes" => !is_post,
        other => {
            if let Some(name) = other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/console"))
            {
                return !name.contains('/');
            }
            // The direct hosted-key advance is POST-only.
            is_post
                && other
                    .strip_prefix("channels/")
                    .and_then(|rest| rest.strip_suffix("/advance"))
                    .is_some_and(|name| !name.contains('/'))
        }
    }
}

/// Dispatch a nested-canonical registry console request from the router
/// fallback.
///
/// The flat `/{slug}/-/…` console routes capture only a single-segment slug,
/// so a registry whose canonical path has slashes (`acme/infra/prod/cdn`)
/// never matches them and lands in [`crate::server`]'s catch-all. This
/// function recognizes the console `/-/` sub-paths there — `settings`
/// (the GET management landing), `settings/visibility` and `settings/delete`
/// (POST-only mutations), `settings/tokens` (and `/revoke`, `/rotate`),
/// `settings/config` (GET form + POST submit), `changes` (GET),
/// `channels/{name}/console`, `channels/{name}/advance` (the POST-only direct
/// hosted-key advance), `keys`, `keys/rotate`, `publishes`— for both `GET` and
/// `POST`, resolving the registry by longest-prefix over the path before the
/// `/-/` marker.
///
/// Returns `None` when the path is not a console page (so the caller falls
/// back to the browse-page resolver), `Some(response)` otherwise.
pub(crate) async fn dispatch_nested(
    state: &Arc<AppState>,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: axum::body::Bytes,
) -> Option<Response> {
    let path = uri.path().trim_start_matches('/');
    let (left, right) = path.split_once("/-/")?;
    let right = right.trim_end_matches('/');
    let is_post = method == axum::http::Method::POST;

    // Classify the `/-/` tail *before* touching the registry or session: a
    // browse page (`packages`, `channels/{name}`, …) is not a console path,
    // so return `None` immediately and let the browse resolver handle it
    // (rather than redirecting an anonymous browser to /login).
    if !is_console_path(right, is_post) {
        return None;
    }
    let registry = match resolve_by_prefix(state, left.trim_end_matches('/')) {
        Ok(Some((reg, tail))) if tail.is_empty() => reg,
        Ok(_) => return None,
        Err(err) => return Some(internal(err)),
    };

    // Console pages are human-only: require a session now that the path is
    // known to be a console page.
    let session = match require_session(state, headers) {
        Ok(s) => s,
        Err(resp) => return Some(*resp),
    };
    let form_str = String::from_utf8_lossy(&body);

    // The `?page=` of a paginated console read (tokens, keys); the nested path
    // has no axum `Query` extractor, so parse it by hand.
    let page_number = uri
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "page")
                .and_then(|(_, v)| v.parse::<usize>().ok())
        })
        .unwrap_or(1)
        .max(1);

    let fields = parse_form(&form_str);
    let response = match (right, is_post) {
        ("settings/tokens", false) => tokens_view(state, &session, &registry, headers, page_number),
        ("settings/tokens", true) => tokens_create_action(
            state,
            &session,
            &registry,
            field(&fields, "csrf"),
            fields.contains_key("perm_read"),
            fields.contains_key("perm_publish"),
        ),
        ("settings/tokens/revoke", true) => tokens_modify_action(
            state,
            &session,
            &registry,
            field(&fields, "csrf"),
            field(&fields, "token_id"),
            false,
        ),
        ("settings/tokens/rotate", true) => tokens_modify_action(
            state,
            &session,
            &registry,
            field(&fields, "csrf"),
            field(&fields, "token_id"),
            true,
        ),
        ("settings/config", false) => config_edit_view(state, &session, &registry, None).await,
        ("settings/config", true) => {
            config_submit_action(
                state,
                &session,
                &registry,
                field(&fields, "csrf"),
                field(&fields, "contents"),
            )
            .await
        }
        ("settings/serving", false) => serving_view(state, &session, &registry, None),
        ("settings/serving", true) => serving_action(state, &session, &registry, &fields),
        ("settings", false) => registry_settings_view(state, &session, &registry, None),
        ("settings/visibility", true) => registry_visibility_action(
            state,
            &session,
            &registry,
            field(&fields, "csrf"),
            field(&fields, "visibility"),
        ),
        ("settings/delete", true) => registry_delete_action(
            state,
            &session,
            &registry,
            field(&fields, "csrf"),
            field(&fields, "confirm"),
        ),
        ("changes", false) => changes_view(state, &session, &registry),
        ("keys", false) => keys_view(state, &session, &registry, headers, page_number),
        ("keys/rotate", false) => keys_rotate_view(state, &session, &registry, headers),
        ("publishes", false) => publishes_view(state, &session, &registry, headers),
        (other, true) if other.ends_with("/advance") => {
            // channels/{name}/advance (POST): the direct hosted-key advance.
            // `is_console_path` already proved this matches.
            let name = other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/advance"))
                .filter(|name| !name.contains('/'))?
                .to_string();
            advance_direct_action(
                state,
                &session,
                &registry,
                &name,
                field(&fields, "csrf"),
                field(&fields, "release"),
                fields.get("partitions").map(String::as_str),
            )
            .await
        }
        (other, _) => {
            // channels/{name}/console (GET renders the view, POST prepares);
            // `is_console_path` already proved this matches.
            let name = other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/console"))
                .filter(|name| !name.contains('/'))?
                .to_string();
            if is_post {
                channel_advance_action(
                    state,
                    &session,
                    &registry,
                    &name,
                    field(&fields, "csrf"),
                    field(&fields, "release"),
                    fields.get("partitions").map(String::as_str),
                )
                .await
            } else {
                if let Err(deny) = authorize_registry_read(state, &registry, headers) {
                    return Some(*deny);
                }
                render_channel_console(state, &session, &registry, &name, None, None)
            }
        }
    };
    Some(response)
}

/// Decode an `application/x-www-form-urlencoded` body into a field map.
fn parse_form(body: &str) -> std::collections::HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The string value of `key` in a decoded form, or `""` when absent.
fn field<'a>(fields: &'a std::collections::HashMap<String, String>, key: &str) -> &'a str {
    fields.get(key).map(String::as_str).unwrap_or("")
}

// -- registry resolution for console pages ----------------------------------

/// Resolve a registry by its flat slug, or by longest-prefix over the full
/// request path for a nested-canonical slug.
///
/// The flat `/{slug}/...` routes capture only the first segment, so a nested
/// registry's settings page must reconstruct the canonical prefix from the
/// request URI.
fn resolve_registry(
    state: &AppState,
    slug: &str,
    uri: &axum::http::Uri,
) -> anyhow::Result<Option<RegistryRecord>> {
    if let Some(reg) = state.db.registry_by_slug(slug)? {
        return Ok(Some(reg));
    }
    // Nested: strip the trailing `/-/...` marker and resolve by prefix.
    let path = uri.path().trim_start_matches('/');
    let head = path.split("/-/").next().unwrap_or(path);
    match resolve_by_prefix(state, head.trim_end_matches('/'))? {
        Some((reg, _)) => Ok(Some(reg)),
        None => Ok(None),
    }
}

// -- registry tokens --------------------------------------------------------

/// `GET /{slug}/-/settings/tokens` — the caller's tokens at the registry.
async fn tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Query(page): Query<PageQuery>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokens_view(&state, &session, &registry, &headers, page.page())
}

/// Render the tokens page (read path): visibility-gated, no result banner.
fn tokens_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
    page_number: usize,
) -> Response {
    // Reads follow registry visibility (404 a hidden registry).
    if let Err(deny) = authorize_registry_read(state, registry, headers) {
        return *deny;
    }
    render_tokens(state, session, registry, None, page_number)
}

/// The token-create action: CSRF + TokensSelf gate, mint, show secret once.
fn tokens_create_action(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    want_read: bool,
    want_publish: bool,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    // Minting a publish-scoped API token outlives the session, so it is a
    // credential-minting operation and gates on sudo (M-1).
    if let Err(resp) = require_sudo(session) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if !session.allows(&state.db, Permission::TokensSelf, &scope) {
        return (StatusCode::FORBIDDEN, "tokens.self required").into_response();
    }
    let mut perms = Vec::new();
    if want_read {
        perms.push(Permission::Read);
    }
    if want_publish {
        perms.push(Permission::Publish);
    }
    // A token may never exceed the owner's own grants: keep only requested
    // permissions the user actually holds at the scope.
    let grants = match session.grants(&state.db) {
        Ok(grants) => grants,
        Err(err) => return internal(err),
    };
    perms.retain(|p| iam::allow(&grants, *p, &scope));
    let (_, secret) = match state.db.create_token(
        session.principal(),
        scope.as_str(),
        &perms,
        Some("created via console"),
        None,
    ) {
        Ok(pair) => pair,
        Err(err) => return internal(err),
    };
    render_tokens(
        state,
        session,
        registry,
        Some(("New token created", &secret)),
        1,
    )
}

/// The token revoke/rotate action: CSRF + ownership gate, then mutate.
///
/// `rotate = true` rotates (showing the new secret once); `false` revokes.
fn tokens_modify_action(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    token_id: &str,
    rotate: bool,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    if let Err(resp) = ensure_owns_token(state, session, token_id) {
        return *resp;
    }
    // Rotation mints a fresh secret (a new credential), so it gates on sudo;
    // revocation only deadens a credential and does not (M-1).
    if rotate {
        if let Err(resp) = require_sudo(session) {
            return *resp;
        }
        match state.db.rotate_token(token_id) {
            Ok(Some((_, secret))) => render_tokens(
                state,
                session,
                registry,
                Some(("Token rotated", &secret)),
                1,
            ),
            Ok(None) => {
                Redirect::to(&format!("/{}/-/settings/tokens", registry.slug)).into_response()
            }
            Err(err) => internal(err),
        }
    } else {
        match state.db.revoke_token(token_id) {
            Ok(()) => {
                Redirect::to(&format!("/{}/-/settings/tokens", registry.slug)).into_response()
            }
            Err(err) => internal(err),
        }
    }
}

/// Render the tokens page, optionally with a one-time secret result.
fn render_tokens(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<(&str, &str)>,
    page_number: usize,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    let can_create = session.allows(&state.db, Permission::TokensSelf, &scope);
    // List the caller's own tokens; filter to this registry scope.
    let all = match state.db.list_tokens_for(session.principal()) {
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
struct TokenCreateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    perm_read: Option<String>,
    #[serde(default)]
    perm_publish: Option<String>,
}

/// `POST /{slug}/-/settings/tokens` — mint a token at the registry scope.
///
/// Requires `TokensSelf`. The secret is shown exactly once on the result
/// page.
async fn tokens_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<TokenCreateForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokens_create_action(
        &state,
        &session,
        &registry,
        &form.csrf,
        form.perm_read.is_some(),
        form.perm_publish.is_some(),
    )
}

/// `POST` token revoke/rotate form: the target token id.
#[derive(serde::Deserialize)]
struct TokenIdForm {
    #[serde(default)]
    csrf: String,
    token_id: String,
}

/// `POST /{slug}/-/settings/tokens/revoke` — revoke one of the caller's tokens.
async fn tokens_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<TokenIdForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokens_modify_action(
        &state,
        &session,
        &registry,
        &form.csrf,
        &form.token_id,
        false,
    )
}

/// `POST /{slug}/-/settings/tokens/rotate` — rotate one of the caller's tokens.
///
/// The new secret is shown exactly once.
async fn tokens_rotate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<TokenIdForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokens_modify_action(
        &state,
        &session,
        &registry,
        &form.csrf,
        &form.token_id,
        true,
    )
}

/// Verify the session user owns the token being revoked/rotated, else 403.
fn ensure_owns_token(
    state: &AppState,
    session: &Session,
    token_id: &str,
) -> Result<(), Box<Response>> {
    let owned = state
        .db
        .list_tokens_for(session.principal())
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
async fn channel_console(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, name)): Path<(String, String)>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(deny) = authorize_registry_read(&state, &registry, &headers) {
        return *deny;
    }
    render_channel_console(&state, &session, &registry, &name, None, None)
}

/// Render the channel console.
///
/// `prepared` carries a BYO-key prepared operation (`(change_id, command)`) to
/// echo; `advanced` carries a hosted-key direct-advance success message. The
/// page renders a real (hosted-key) advance form when the registry has a
/// hosted key bound, and the prepared-operation form otherwise.
fn render_channel_console(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    name: &str,
    prepared: Option<(&str, &str)>,
    advanced: Option<&str>,
) -> Response {
    let result = (|| {
        let status = state.db.index_status(registry.id)?;
        let channels = state.db.list_channels(registry.id)?;
        let Some(channel) = channels.into_iter().find(|c| c.name == name) else {
            return Ok(None);
        };
        let scope = Scope::parse(&registry.slug);
        let can_advance = session.allows(&state.db, Permission::ChannelAdvance, &scope);
        let hosted_key = match registry.hosted_key_id {
            Some(id) => state.db.hosted_key(id)?.map(|k| k.key_id),
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
    })();
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /{slug}/-/channels/{name}/console` form: the advance request.
#[derive(serde::Deserialize)]
struct AdvanceForm {
    #[serde(default)]
    csrf: String,
    release: String,
    partitions: Option<String>,
}

/// `POST /{slug}/-/channels/{name}/console` — prepare a channel advance.
///
/// Requires `ChannelAdvance`. Produces a prepared operation (a draft
/// change-set) and renders the exact `apr channel advance --from-hub <id>`
/// command for the maintainer to sign and push locally.
async fn channel_advance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<AdvanceForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    channel_advance_action(
        &state,
        &session,
        &registry,
        &name,
        &form.csrf,
        &form.release,
        form.partitions.as_deref(),
    )
    .await
}

/// The channel-advance action: CSRF + ChannelAdvance gate, then record a
/// prepared operation and render its `apr` command.
async fn channel_advance_action(
    state: &AppState,
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
    if !session.allows(&state.db, Permission::ChannelAdvance, &scope) {
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
        &state.db,
        &session.principal(),
        &session.email,
        &registry.slug,
        name,
        release,
        partitions,
    ) {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    let registry_url = format!(
        "{}/{}",
        state.external_url.trim_end_matches('/'),
        registry.slug
    );
    let command = config::advance_command(&registry_url, &change_id);
    render_channel_console(
        state,
        session,
        registry,
        name,
        Some((change_id.as_str(), &command)),
        None,
    )
}

/// `POST /{slug}/-/channels/{name}/advance` — directly advance a hosted-key
/// channel.
///
/// Requires `ChannelAdvance` and a registry with a bound hosted key. The hub
/// signs the partition tags with the hosted key and writes them to the
/// surface, then re-indexes; the advance is audited. A registry without a
/// hosted key falls through to the prepared-operation flow instead.
async fn channel_advance_direct(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<AdvanceForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    advance_direct_action(
        &state,
        &session,
        &registry,
        &name,
        &form.csrf,
        &form.release,
        form.partitions.as_deref(),
    )
    .await
}

/// The direct hosted-key advance action: CSRF + `ChannelAdvance` gate, then
/// sign and apply the advance server-side (or fall back to a prepared
/// operation when no hosted key is bound).
async fn advance_direct_action(
    state: &AppState,
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
    if !session.allows(&state.db, Permission::ChannelAdvance, &scope) {
        return (StatusCode::FORBIDDEN, "channel.advance required").into_response();
    }
    // No hosted key bound: fall back to recording a prepared operation.
    if registry.hosted_key_id.is_none() {
        return channel_advance_action(state, session, registry, name, csrf, release, partitions)
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
    let when = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let result = crate::signing::advance_channel(
        &state.db,
        state.sealer.as_ref(),
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
            render_channel_console(state, session, registry, name, None, Some(&message))
        }
        Err(err) => {
            // A failed advance (e.g. unknown release, below floor) is a
            // client/operator error, not an internal fault: surface the cause.
            (StatusCode::BAD_REQUEST, format!("advance failed: {err:#}")).into_response()
        }
    }
}

// -- hosted signing keys ----------------------------------------------------

/// `GET /-/org/{org}/keys` — the org hosted-key enrollment page.
///
/// Gated to org admins (`KeysManage` at the org scope). A member without it
/// gets `403` (the org is known to them); a non-member gets `404`.
async fn org_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_keys(&state, &session, &org_slug, None)
}

/// Render the org hosted-keys page, optionally echoing a just-created key's
/// public trusted-key line.
fn render_org_keys(
    state: &AppState,
    session: &Session,
    org_slug: &str,
    created: Option<&str>,
) -> Response {
    let scope = Scope::parse(org_slug);
    if !session.allows(&state.db, Permission::KeysManage, &scope) {
        if session.allows(&state.db, Permission::Read, &scope) {
            return (StatusCode::FORBIDDEN, "keys.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(org_slug)? else {
            return Ok(None);
        };
        let keys = state.db.list_hosted_keys(org.id)?;
        let registries: Vec<RegistryRecord> = state
            .db
            .list_registries()?
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
    })();
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/keys` form: enroll a key or attach one to a registry.
#[derive(serde::Deserialize)]
struct OrgKeysForm {
    #[serde(default)]
    csrf: String,
    /// `create` (enroll a new key) or `attach` (bind one to a registry).
    op: String,
    /// For `create`: the operator-chosen key id.
    #[serde(default)]
    key_id: String,
    /// For `attach`: the canonical registry slug to bind the key to.
    #[serde(default)]
    registry: String,
    /// For `attach`: the hosted key's id, or empty to detach.
    #[serde(default)]
    hosted_key_id: String,
}

/// `POST /-/org/{org}/keys` — enroll or attach a hosted signing key.
///
/// Requires `KeysManage` at the org scope. `create` enrolls a fresh key
/// (audited); `attach` binds a key to one of the org's registries (or detaches
/// when the key id is empty). Both flows are CSRF-checked.
async fn org_keys_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Form(form): Form<OrgKeysForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_csrf(&session, &form.csrf) {
        return *resp;
    }
    // Enrolling or attaching a hosted signing key changes what the org trusts
    // to sign, so both ops gate on sudo (M-1).
    if let Err(resp) = require_sudo(&session) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session.allows(&state.db, Permission::KeysManage, &scope) {
        if session.allows(&state.db, Permission::Read, &scope) {
            return (StatusCode::FORBIDDEN, "keys.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(org) = (match state.db.org_by_slug(&org_slug) {
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
            let public = match state
                .db
                .create_hosted_key(state.sealer.as_ref(), org.id, key_id)
            {
                Ok(line) => line,
                Err(err) => {
                    return (StatusCode::BAD_REQUEST, format!("enroll failed: {err:#}"))
                        .into_response()
                }
            };
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "hosted_key.create",
                &org_slug,
                None,
                None,
                None,
                Some(key_id),
            ) {
                return internal(err);
            }
            render_org_keys(&state, &session, &org_slug, Some(&public))
        }
        "attach" => {
            let Some(registry) = (match state.db.registry_by_slug(form.registry.trim()) {
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
            // A non-empty key must exist and belong to this org.
            if let Some(id) = hosted_key_id {
                match state.db.hosted_key(id) {
                    Ok(Some(k)) if k.org_id == org.id => {}
                    Ok(_) => {
                        return (StatusCode::BAD_REQUEST, "no such hosted key in this org")
                            .into_response()
                    }
                    Err(err) => return internal(err),
                }
            }
            if let Err(err) = state.db.set_registry_hosted_key(registry.id, hosted_key_id) {
                return internal(err);
            }
            let detail = serde_json::json!({ "hosted_key_id": hosted_key_id }).to_string();
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "hosted_key.attach",
                &registry.slug,
                None,
                None,
                None,
                Some(&detail),
            ) {
                return internal(err);
            }
            render_org_keys(&state, &session, &org_slug, None)
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- webhooks ---------------------------------------------------------------

/// `GET /-/org/{org}/webhooks` — the org webhook management page.
async fn org_webhooks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_webhooks(&state, &session, &org_slug, None)
}

/// Render the org webhooks page, optionally echoing a just-created secret once.
fn render_org_webhooks(
    state: &AppState,
    session: &Session,
    org_slug: &str,
    created_secret: Option<&str>,
) -> Response {
    let scope = Scope::parse(org_slug);
    if !session.allows(&state.db, Permission::MembersManage, &scope) {
        if session.allows(&state.db, Permission::Read, &scope) {
            return (StatusCode::FORBIDDEN, "members.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(org_slug)? else {
            return Ok(None);
        };
        let webhooks = state.db.list_webhooks(org.id)?;
        Ok::<_, anyhow::Error>(Some(console::org_webhooks_page(
            &session.email,
            &org,
            &session.csrf(),
            &webhooks,
            created_secret,
            Instant::now(),
        )))
    })();
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/webhooks` — create or delete a webhook subscription.
///
/// Requires `MembersManage` at the org scope (matching the RPC). The `events`
/// field repeats (one per checked box), so the body is parsed by hand rather
/// than via a serde `Form`. Both operations are CSRF-checked and audited.
async fn org_webhooks_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    // Parse the form by hand: `events` repeats, which a serde `Form` cannot
    // collect into a `Vec`.
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
    if !session.allows(&state.db, Permission::MembersManage, &scope) {
        if session.allows(&state.db, Permission::Read, &scope) {
            return (StatusCode::FORBIDDEN, "members.manage required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(org) = (match state.db.org_by_slug(&org_slug) {
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
            // The delivery worker POSTs to this URL from inside the hub
            // network, so reject loopback/link-local/private/non-http(s)
            // targets up front for a friendly error (create_webhook re-checks).
            if let Err(err) = crate::fetch::is_safe_remote_url(url) {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("rejecting webhook url: {err:#}"),
                )
                    .into_response();
            }
            // Only the registry's own event vocabulary is accepted.
            let known: Vec<&str> = console::WEBHOOK_EVENT_TYPES
                .iter()
                .map(|(e, _)| *e)
                .collect();
            if let Some(bad) = events.iter().find(|e| !known.contains(&e.as_str())) {
                return (StatusCode::BAD_REQUEST, format!("unknown event: {bad}")).into_response();
            }
            // Generate a secret when the operator left it blank; echo it once.
            let provided = field("secret").trim().to_string();
            let generated = provided.is_empty();
            let secret = if generated {
                crate::auth::token::generate_token().0
            } else {
                provided
            };
            let id = match state.db.create_webhook(org.id, url, &secret, &events) {
                Ok(id) => id,
                Err(err) => return internal(err),
            };
            let detail = serde_json::json!({ "id": id, "url": url, "events": events }).to_string();
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "webhook.create",
                &org_slug,
                None,
                None,
                None,
                Some(&detail),
            ) {
                return internal(err);
            }
            // Only reveal a secret the hub generated; a provided one is known.
            render_org_webhooks(
                &state,
                &session,
                &org_slug,
                generated.then_some(secret.as_str()),
            )
        }
        "delete" => {
            let Ok(webhook_id) = field("webhook_id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad webhook id").into_response();
            };
            // The webhook must belong to this org (no cross-org deletion).
            match state.db.webhook(webhook_id) {
                Ok(Some(w)) if w.org_id == org.id => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such webhook").into_response(),
                Err(err) => return internal(err),
            }
            if let Err(err) = state.db.delete_webhook(webhook_id) {
                return internal(err);
            }
            let detail = serde_json::json!({ "id": webhook_id }).to_string();
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "webhook.delete",
                &org_slug,
                None,
                None,
                None,
                Some(&detail),
            ) {
                return internal(err);
            }
            render_org_webhooks(&state, &session, &org_slug, None)
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- single sign-on (OIDC IdP + email domains) ------------------------------

/// `GET /-/org/{org}/sso` — the org SSO (OIDC IdP + domains) page.
async fn org_sso(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_org_sso(&state, &session, &org_slug, None)
}

/// Whether `session` may verify captured domains: an *instance* admin only
/// (`iam.admin` at the root scope). Verifying a domain routes other users'
/// logins, so it is a trusted-operator action, never org self-service.
fn can_verify_domains(state: &AppState, session: &Session) -> bool {
    session.allows(&state.db, Permission::IamAdmin, &Scope::parse(""))
}

/// Render the org SSO page, optionally with a one-line notice (e.g. a domain's
/// freshly minted DNS-TXT challenge).
fn render_org_sso(
    state: &AppState,
    session: &Session,
    org_slug: &str,
    notice: Option<&str>,
) -> Response {
    let scope = Scope::parse(org_slug);
    // SSO config is org-owner-level (it shapes how the org authenticates).
    if !session.allows(&state.db, Permission::IamAdmin, &scope) {
        if session.allows(&state.db, Permission::Read, &scope) {
            return (StatusCode::FORBIDDEN, "iam.admin required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = (|| {
        let Some(org) = state.db.org_by_slug(org_slug)? else {
            return Ok(None);
        };
        let idp = state.db.idp_config(org.id)?;
        let domains = state.db.list_org_domains(org.id)?;
        Ok::<_, anyhow::Error>(Some(console::org_sso_page(
            &session.email,
            &org,
            &session.csrf(),
            idp.as_ref(),
            &domains,
            can_verify_domains(state, session),
            notice,
            Instant::now(),
        )))
    })();
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /-/org/{org}/sso` — configure the IdP or manage captured domains.
///
/// Requires `IamAdmin` at the org scope for every op except `verify-domain`,
/// which additionally requires *instance* `IamAdmin` (the trusted DNS check).
/// All ops are CSRF-checked and audited.
async fn org_sso_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let fields = parse_form(&String::from_utf8_lossy(&body));
    let field = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");

    if let Err(resp) = check_csrf(&session, field("csrf")) {
        return *resp;
    }
    // Pointing or removing the org's IdP (and the domain claims that route
    // logins to it) changes who is trusted to authenticate as the org, so
    // every op here gates on sudo (M-1).
    if let Err(resp) = require_sudo(&session) {
        return *resp;
    }
    let scope = Scope::parse(&org_slug);
    if !session.allows(&state.db, Permission::IamAdmin, &scope) {
        if session.allows(&state.db, Permission::Read, &scope) {
            return (StatusCode::FORBIDDEN, "iam.admin required").into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(org) = (match state.db.org_by_slug(&org_slug) {
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
            // The client secret is write-only: a new value is sealed; a blank
            // one keeps any existing sealed secret (so editing other fields
            // does not wipe it).
            let existing = match state.db.idp_config(org.id) {
                Ok(cfg) => cfg,
                Err(err) => return internal(err),
            };
            let client_secret_enc = {
                let provided = field("client_secret");
                if provided.is_empty() {
                    existing.and_then(|c| c.client_secret_enc)
                } else {
                    match state.sealer.seal(provided) {
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
            if let Err(err) = state.db.upsert_idp_config(&config) {
                return internal(err);
            }
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "idp.set",
                &org_slug,
                None,
                None,
                None,
                Some(&config.issuer),
            ) {
                return internal(err);
            }
            render_org_sso(
                &state,
                &session,
                &org_slug,
                Some("Identity provider saved."),
            )
        }
        "remove-idp" => {
            if let Err(err) = state.db.delete_idp_config(org.id) {
                return internal(err);
            }
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "idp.remove",
                &org_slug,
                None,
                None,
                None,
                None,
            ) {
                return internal(err);
            }
            render_org_sso(
                &state,
                &session,
                &org_slug,
                Some("Identity provider removed."),
            )
        }
        "add-domain" => {
            let domain = field("domain").trim().to_lowercase();
            if domain.is_empty() || !domain.contains('.') {
                return (StatusCode::BAD_REQUEST, "a valid domain is required").into_response();
            }
            // A domain is a global SSO-routing key owned by at most one org;
            // reject a cross-tenant claim with a 409 rather than letting the
            // upsert silently seize another org's verified domain (H7). The
            // `add_org_domain` call below re-checks this as defense-in-depth.
            match state.db.org_domain(&domain) {
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
            let challenge = match state.db.add_org_domain(org.id, &domain) {
                Ok(c) => c,
                Err(err) => return internal(err),
            };
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "domain.capture",
                &org_slug,
                None,
                None,
                None,
                Some(&domain),
            ) {
                return internal(err);
            }
            render_org_sso(
                &state,
                &session,
                &org_slug,
                Some(&format!(
                    "Captured {domain} (unverified). Publish this TXT record: {challenge}"
                )),
            )
        }
        "verify-domain" => {
            // The trust boundary: only an instance operator verifies (it routes
            // other people's logins). The challenge is published in DNS; the
            // operator is trusted to have confirmed it.
            if !can_verify_domains(&state, &session) {
                return (
                    StatusCode::FORBIDDEN,
                    "domain verification is an instance-operator action",
                )
                    .into_response();
            }
            let domain = field("domain").trim().to_lowercase();
            // The domain must be claimed by *this* org before verification.
            match state.db.org_domain(&domain) {
                Ok(Some(d)) if d.org_id == org.id => {}
                Ok(_) => {
                    return (StatusCode::NOT_FOUND, "domain not claimed by this org")
                        .into_response()
                }
                Err(err) => return internal(err),
            }
            if let Err(err) = state.db.verify_org_domain(&domain) {
                return internal(err);
            }
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "domain.verify",
                &org_slug,
                None,
                None,
                None,
                Some(&domain),
            ) {
                return internal(err);
            }
            render_org_sso(
                &state,
                &session,
                &org_slug,
                Some(&format!("Verified {domain}.")),
            )
        }
        "remove-domain" => {
            let domain = field("domain").trim().to_lowercase();
            if let Err(err) = state.db.delete_org_domain(org.id, &domain) {
                return internal(err);
            }
            if let Err(err) = state.db.record_audit(
                "user",
                Some(session.auth.user_id),
                &session.email,
                "domain.remove",
                &org_slug,
                None,
                None,
                None,
                Some(&domain),
            ) {
                return internal(err);
            }
            render_org_sso(
                &state,
                &session,
                &org_slug,
                Some(&format!("Removed {domain}.")),
            )
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- serving frontends + mirror ---------------------------------------------

/// `GET /{slug}/-/settings/serving` — the serving & mirror management page.
async fn serving(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    serving_view(&state, &session, &registry, None)
}

/// Render the serving & mirror page; `RegistryConfigure`-gated at the registry
/// scope (a reader without it gets 403, a non-member 404 via visibility).
fn serving_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    notice: Option<&str>,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    if !session.allows(&state.db, Permission::RegistryConfigure, &scope) {
        if let Err(deny) = authorize_registry_read(state, registry, &HeaderMap::new()) {
            return *deny;
        }
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let result = (|| {
        let frontends = state.db.list_frontends(registry.id)?;
        let mirror = state.db.mirror_source(registry.id)?;
        Ok::<_, anyhow::Error>(console::serving_page(
            &session.email,
            registry,
            &session.csrf(),
            &frontends,
            mirror.as_ref(),
            notice,
            Instant::now(),
        ))
    })();
    match result {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

/// `POST /{slug}/-/settings/serving` — add/delete a frontend or set/clear the
/// mirror config.
async fn serving_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let fields = parse_form(&String::from_utf8_lossy(&body));
    serving_action(&state, &session, &registry, &fields)
}

/// Apply a serving/mirror mutation. Shared by the flat route and the
/// nested-canonical [`dispatch_nested`] path; `RegistryConfigure`-gated and
/// CSRF-checked; every op is audited.
fn serving_action(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    fields: &std::collections::HashMap<String, String>,
) -> Response {
    let field = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
    if let Err(resp) = check_csrf(session, field("csrf")) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if !session.allows(&state.db, Permission::RegistryConfigure, &scope) {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let audit = |action: &str, detail: &str| {
        state.db.record_audit(
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
    };

    match field("op") {
        "add-frontend" => {
            let domain = field("domain").trim();
            if domain.is_empty() {
                return (StatusCode::BAD_REQUEST, "domain is required").into_response();
            }
            let priority: i64 = field("consumer_priority").trim().parse().unwrap_or(100);
            // create_frontend validates the mode and rejects unsafe domains.
            let created = state.db.create_frontend(
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
            );
            match created {
                Ok(_) => {}
                Err(err) => return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
            }
            if let Err(err) = audit("frontend.add", domain) {
                return internal(err);
            }
            serving_view(state, session, registry, Some("Frontend added."))
        }
        "delete-frontend" => {
            let Ok(id) = field("id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad frontend id").into_response();
            };
            // The frontend must belong to this registry.
            match state.db.list_frontends(registry.id) {
                Ok(list) if list.iter().any(|f| f.id == id) => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such frontend").into_response(),
                Err(err) => return internal(err),
            }
            if let Err(err) = state.db.delete_frontend(id) {
                return internal(err);
            }
            if let Err(err) = audit("frontend.delete", &id.to_string()) {
                return internal(err);
            }
            serving_view(state, session, registry, Some("Frontend deleted."))
        }
        "set-mirror" => {
            let upstream = field("upstream_url").trim();
            if upstream.is_empty() {
                return (StatusCode::BAD_REQUEST, "upstream URL is required").into_response();
            }
            let secs: i64 = field("schedule_secs").trim().parse().unwrap_or(3600);
            // create_mirror_source validates the mode and rejects SSRF targets.
            let r = state.db.create_mirror_source(
                registry.id,
                upstream,
                match field("mode") {
                    "pullthrough" => "pullthrough",
                    _ => "full",
                },
                field("verify") == "1",
                secs,
            );
            if let Err(err) = r {
                return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response();
            }
            if let Err(err) = audit("mirror.set", upstream) {
                return internal(err);
            }
            serving_view(
                state,
                session,
                registry,
                Some("Mirror configuration saved."),
            )
        }
        "remove-mirror" => {
            if let Err(err) = state.db.delete_mirror_source(registry.id) {
                return internal(err);
            }
            if let Err(err) = audit("mirror.remove", &registry.slug) {
                return internal(err);
            }
            serving_view(state, session, registry, Some("Stopped mirroring."))
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- keys -------------------------------------------------------------------

/// `GET /{slug}/-/keys` — the key roster management page.
async fn keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Query(page): Query<PageQuery>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    keys_view(&state, &session, &registry, &headers, page.page())
}

/// Render the key roster page: visibility-gated, KeysManage reveals the
/// rotation wizard link.
fn keys_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
    page_number: usize,
) -> Response {
    if let Err(deny) = authorize_registry_read(state, registry, headers) {
        return *deny;
    }
    let roster = match state.db.list_roster(registry.id) {
        Ok(roster) => roster,
        Err(err) => return internal(err),
    };
    let can_manage = session.allows(
        &state.db,
        Permission::KeysManage,
        &Scope::parse(&registry.slug),
    );
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
async fn keys_rotate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    keys_rotate_view(&state, &session, &registry, &headers)
}

/// Render the rotation wizard: visibility-gated.
fn keys_rotate_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Response {
    if let Err(deny) = authorize_registry_read(state, registry, headers) {
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
async fn publishes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    publishes_view(&state, &session, &registry, &headers)
}

/// Render the publish-pipeline view: visibility-gated.
fn publishes_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Response {
    if let Err(deny) = authorize_registry_read(state, registry, headers) {
        return *deny;
    }
    let result = (|| {
        let status = state.db.index_status(registry.id)?;
        let releases = state.db.list_releases(registry.id)?;
        // Recent publish/index activity, filtered to this registry scope.
        let audit: Vec<_> = state
            .db
            .list_audit(&registry.slug)?
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
    })();
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
async fn config_edit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    config_edit_view(&state, &session, &registry, None).await
}

/// Render the config-edit page, optionally with a just-created change-request
/// `result` (its change id and merge command).
async fn config_edit_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<(&str, &str)>,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    let can_edit = session.allows(&state.db, Permission::RegistryConfigure, &scope);
    let current = match current_registry_toml(state, registry).await {
        Ok(toml) => toml,
        Err(err) => return internal(err),
    };
    Html(console::config_edit_page(
        &session.email,
        registry,
        &session.csrf(),
        &current,
        can_edit,
        result,
        Instant::now(),
    ))
    .into_response()
}

/// Load a registry's current committed `registry.toml`, or an empty string
/// when the registry has not been indexed yet (no HEAD to read from).
async fn current_registry_toml(
    state: &AppState,
    registry: &RegistryRecord,
) -> anyhow::Result<String> {
    let Some(head_hex) = state
        .db
        .index_status(registry.id)?
        .and_then(|s| s.last_indexed_commit)
    else {
        return Ok(String::new());
    };
    let head = crate::surface::object::Oid::from_hex(&head_hex)?;
    let fetch = crate::gitwrite::fetcher_for_registry(&state.db, registry)?;
    Ok(
        crate::gitwrite::load_committed_file(fetch.as_ref(), head, "registry.toml")
            .await?
            .unwrap_or_default(),
    )
}

/// The config-edit submission form body.
#[derive(serde::Deserialize)]
struct ConfigForm {
    #[serde(default)]
    csrf: String,
    contents: String,
}

/// `POST /{slug}/-/settings/config` — submit a git-backed config change request.
///
/// CSRF-checked, `registry.configure`-gated: writes the draft-signed change
/// request to `refs/hub/changes/<id>` via
/// [`crate::gitwrite::propose_config_change`] and re-renders the page with the
/// new change id and the `apr change merge` command to run.
async fn config_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
    Form(form): Form<ConfigForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    config_submit_action(&state, &session, &registry, &form.csrf, &form.contents).await
}

/// Process a config-change submission for a resolved registry.
///
/// CSRF-checked then `registry.configure`-gated; proposes the change request
/// and re-renders the config-edit page with the new change id and merge
/// command, or a `400` on a proposal error.
async fn config_submit_action(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    csrf: &str,
    contents: &str,
) -> Response {
    if let Err(resp) = check_csrf(session, csrf) {
        return *resp;
    }
    let scope = Scope::parse(&registry.slug);
    if !session.allows(&state.db, Permission::RegistryConfigure, &scope) {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let proposed = crate::gitwrite::propose_config_change(
        &state.db,
        state.sealer.as_ref(),
        registry,
        "registry.toml",
        contents,
        "user",
        Some(session.auth.user_id),
        &session.email,
        unix_now(),
    )
    .await;
    match proposed {
        Ok(proposed) => {
            let merge_url = format!(
                "{}/{}",
                state.external_url.trim_end_matches('/'),
                registry.slug
            );
            let merge_command = crate::gitwrite::merge_command(&merge_url, &proposed.change_id);
            config_edit_view(
                state,
                session,
                registry,
                Some((proposed.change_id.as_str(), &merge_command)),
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
async fn changes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(slug): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri) {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    changes_view(&state, &session, &registry)
}

/// Render the change-request list page for a resolved registry.
///
/// Gated to `audit.read` (admin+). Each draft renders its file diffs (computed
/// from the recorded old/new file contents) and the promotion command.
fn changes_view(state: &AppState, session: &Session, registry: &RegistryRecord) -> Response {
    let scope = Scope::parse(&registry.slug);
    if !session.allows(&state.db, Permission::AuditRead, &scope) {
        return (StatusCode::FORBIDDEN, "audit.read required").into_response();
    }

    let result = (|| {
        let merge_url = format!(
            "{}/{}",
            state.external_url.trim_end_matches('/'),
            registry.slug
        );
        let requests: Vec<console::ChangeRequestView> = state
            .db
            .list_changesets(&registry.slug)?
            .into_iter()
            .filter(|cs| cs.git_ref.is_some())
            .map(|cs| {
                let file_diffs = state
                    .db
                    .list_revisions(&cs.change_id)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| r.object_type == "registry_file")
                    .map(|r| {
                        (
                            r.object_id.clone(),
                            crate::gitwrite::unified_diff(
                                &r.object_id,
                                r.old_json.as_deref().unwrap_or_default(),
                                r.new_json.as_deref().unwrap_or_default(),
                            ),
                        )
                    })
                    .collect();
                let merge_command = crate::gitwrite::merge_command(
                    &merge_url,
                    &config::ChangeId(cs.change_id.clone()),
                );
                console::ChangeRequestView {
                    change_id: cs.change_id,
                    status: cs.status,
                    summary: cs.summary.unwrap_or_default(),
                    actor_label: cs.actor_label,
                    git_commit: cs.git_commit.unwrap_or_default(),
                    file_diffs,
                    merge_command,
                }
            })
            .collect();
        Ok::<_, anyhow::Error>(console::changes_page(
            &session.email,
            registry,
            &requests,
            Instant::now(),
        ))
    })();
    match result {
        Ok(html) => Html(html).into_response(),
        Err(err) => internal(err),
    }
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Percent-encode a string for a query component.
fn urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}
