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
use axum::Router;

use crate::auth::extract::{connect_or_csrf_ok, mint_csrf_token};
use crate::auth::session::{set_cookie_header, COOKIE_NAME, IDLE_TIMEOUT_SECS};
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
        .route("/auth/magic", get(magic_consume))
        .route("/auth/sso", post(login_sso))
        .route("/auth/oidc/start", get(oidc_start))
        .route("/auth/oidc/callback", get(oidc_callback))
        .route("/logout", get(logout))
        .route("/account", get(account))
        .route(
            "/account/sessions/revoke-all",
            post(account_revoke_all_sessions),
        )
        .route("/activate", get(activate_form).post(activate_submit))
        .route("/-/orgs", get(orgs))
        .route("/-/org/{org}", get(org_dashboard))
        .route("/-/org/{org}/audit", get(org_audit))
        .route("/-/org/{org}/members", post(org_invite_member))
        .route("/-/org/{org}/members/remove", post(org_remove_member))
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

// -- login + magic link -----------------------------------------------------

/// `GET /login` — the email-first login form.
async fn login_form(State(_state): State<Arc<AppState>>) -> Response {
    Html(console::login_page(None, Instant::now())).into_response()
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
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Html(console::login_page(
            Some("Enter a valid email address."),
            Instant::now(),
        ))
        .into_response();
    }
    // Rate-limit magic-link issuance on both the target email (the email-bomb
    // victim) and the source IP (the sender) — see [`crate::ratelimit`].
    let now = crate::server::now_secs();
    let ip = crate::server::client_ip_from_headers(&headers);
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
        let start = format!("/auth/oidc/start?org={}", urlencode(&org_slug));
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
    let cookie = match state.db.create_session(user_id, IDLE_TIMEOUT_SECS, 1) {
        Ok(secret) => set_cookie_header(&secret, IDLE_TIMEOUT_SECS),
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
    let cookie = match state.db.create_session(login.user_id, IDLE_TIMEOUT_SECS, 1) {
        Ok(secret) => set_cookie_header(&secret, IDLE_TIMEOUT_SECS),
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
    Html(console::login_page(Some(message), Instant::now())).into_response()
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
    Html(console::account_page(
        &session.email,
        &session.csrf(),
        &tokens,
        Instant::now(),
    ))
    .into_response()
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

// -- device approval (RFC 8628) ---------------------------------------------

/// `GET /activate?user_code=` query.
#[derive(Default, serde::Deserialize)]
struct ActivateQuery {
    user_code: Option<String>,
    message: Option<String>,
}

/// `GET /activate` — the device-approval page.
///
/// Prefills the user code from `?user_code=` and, when it resolves to a live
/// pending grant, shows the requested scope/permissions and the approve form.
async fn activate_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ActivateQuery>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
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
    headers: HeaderMap,
    Form(form): Form<ActivateForm>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
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
async fn orgs(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
        Ok::<_, anyhow::Error>(orgs)
    })();
    match result {
        Ok(orgs) => Html(console::orgs_page(&session.email, &orgs, Instant::now())).into_response(),
        Err(err) => internal(err),
    }
}

/// `GET /-/org/{org}` — the org dashboard.
async fn org_dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
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
            owner_count,
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
            Instant::now(),
        )))
    })();
    match result {
        Ok(Some(html)) => Html(html).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => internal(err),
    }
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
        config::change_membership(
            &state.db,
            &session.principal(),
            &session.email,
            MembershipChange::Grant,
            &Principal::user(invitee),
            &scope,
            role,
        )?;
        let _ = org; // org id reserved for an invitation-table write later.
        Ok::<_, anyhow::Error>(())
    })();
    match result {
        Ok(()) => Redirect::to(&format!("/-/org/{org_slug}")).into_response(),
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
/// function recognizes the console `/-/` sub-paths there — `settings/tokens`
/// (and `/revoke`, `/rotate`), `settings/config` (GET form + POST submit),
/// `changes` (GET), `channels/{name}/console`, `channels/{name}/advance` (the
/// POST-only direct hosted-key advance), `keys`, `keys/rotate`, `publishes`—
/// for both `GET` and `POST`, resolving the registry by longest-prefix over the
/// path before the `/-/` marker.
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

    let fields = parse_form(&form_str);
    let response = match (right, is_post) {
        ("settings/tokens", false) => tokens_view(state, &session, &registry, headers),
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
        ("changes", false) => changes_view(state, &session, &registry),
        ("keys", false) => keys_view(state, &session, &registry, headers),
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
    tokens_view(&state, &session, &registry, &headers)
}

/// Render the tokens page (read path): visibility-gated, no result banner.
fn tokens_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Response {
    // Reads follow registry visibility (404 a hidden registry).
    if let Err(deny) = authorize_registry_read(state, registry, headers) {
        return *deny;
    }
    render_tokens(state, session, registry, None)
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
    if rotate {
        match state.db.rotate_token(token_id) {
            Ok(Some((_, secret))) => {
                render_tokens(state, session, registry, Some(("Token rotated", &secret)))
            }
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

// -- keys -------------------------------------------------------------------

/// `GET /{slug}/-/keys` — the key roster management page.
async fn keys(
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
    keys_view(&state, &session, &registry, &headers)
}

/// Render the key roster page: visibility-gated, KeysManage reveals the
/// rotation wizard link.
fn keys_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
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
