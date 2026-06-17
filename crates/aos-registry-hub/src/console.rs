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
use crate::auth::extract::{connect_or_csrf_ok, mint_csrf_token};
use crate::auth::session::{set_cookie_header, ABSOLUTE_LIFETIME_SECS};
use crate::config;
use crate::db::{Database, RegistryRecord, SessionAuth as DbSession};
use crate::domain::{iam, Permission, Principal, Role, Scope};
use crate::server::{authorize_registry_read, internal, resolve_by_prefix, AppState};
use crate::ui::console;

/// The native-only console routes, merged into the main router by
/// [`crate::server::router`] alongside the shared
/// [`console_router`](aos_registry_core::web::console::console_router).
///
/// RFC-0004 Phase 5 (console-dedup stage B) moved the wasm-clean console
/// handlers into the shared core crate. The routes that remain native are the
/// ones this router registers:
///
/// - the **pre-auth rate-limited** activation/passkey paths
///   (`/auth/passkey/begin`, `/activate`), which read the connecting peer
///   address ([`crate::server::PeerAddr`]) and the reverse-proxy trust flag —
///   neither available to a wasm handler. (The `/login` and `/login/password`
///   paths moved to the shared core router in RFC-0004 Phase 5 stage D: they now
///   meter on the runtime-neutral `x-aos-client-ip` header the hub stamps in
///   [`crate::server::inject_client_ip`].)
/// - the **OIDC flow** (`/auth/sso`, `/auth/oidc/start`, `/auth/oidc/callback`),
///   which makes outbound [`reqwest`] calls through [`crate::auth::oidc`];
/// - the **git-backed config** surface (`/{slug}/-/settings/config`,
///   `/{slug}/-/changes`), which uses [`crate::gitwrite`] and
///   [`crate::surface`].
///
/// Every other console route is served by the shared core router. The
/// nested-canonical fallback ([`dispatch_nested`]) still lives here and reuses
/// the private handler helpers below for slugs whose canonical path has slashes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/sso", post(login_sso))
        .route("/auth/oidc/start", get(oidc_start))
        .route("/auth/oidc/callback", get(oidc_callback))
        // The passkey assertion ceremony is the pre-auth login path and is
        // rate-limited on the source IP, so it stays native (the `finish` half,
        // which mints no rate-limit key, moved to the shared router).
        .route("/auth/passkey/begin", post(passkey_login_begin))
        .route("/activate", get(activate_form).post(activate_submit))
        .route(
            "/{slug}/-/settings/config",
            get(config_edit).post(config_submit),
        )
        .route("/{slug}/-/changes", get(changes))
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
async fn require_session(state: &AppState, headers: &HeaderMap) -> Result<Session, Box<Response>> {
    // Pull the cookie from axum and delegate to the runtime-neutral core
    // resolver (RFC-0004 Phase 5); the only hub-specific behavior is bouncing an
    // anonymous/invalid session to `/login` rather than returning an error.
    let resolved =
        match aos_registry_core::web::session::resolve_session_from_headers(&state.db, headers)
            .await
        {
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

// -- login + magic link ----------------------------------------------------
//
// The `/login` (GET form + POST magic link) and `/login/password` (POST)
// handlers moved to the shared core router in RFC-0004 Phase 5 (console-dedup
// stage D). They rate-limit on the runtime-neutral `x-aos-client-ip` header the
// hub stamps in [`crate::server::inject_client_ip`] instead of the native peer
// socket, so they are wasm-clean and serve both shells. `login_sso` and the
// OIDC flow below stay native (outbound `reqwest`).

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
    let org = match state.db.org_by_slug(org_slug).await {
        Ok(Some(org)) => org,
        Ok(None) => return sso_error("That organization does not exist."),
        Err(err) => return internal(err),
    };
    match crate::auth::oidc::begin_login(&state.db, &state.external_url, org.id, next).await {
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
        .await
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

// -- account ----------------------------------------------------------------

// -- passkeys / WebAuthn ----------------------------------------------------
//
// WebAuthn is the one place the console departs from its no-JS floor: the
// browser's `navigator.credentials` API has no form-only equivalent, so the
// passkey pages serve a small, first-party inline script. The script is gated
// by a per-request CSP nonce (`script-src 'nonce-…'` alongside the global
// `default-src 'self'`), so only that exact `<script nonce=…>` runs — no other
// inline or third-party script is permitted. The script exchanges JSON with the
// begin/finish endpoints, base64url-encoding the binary credential fields.

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
    match crate::auth::webauthn::begin_assertion(&state.db, &rp.id).await {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => internal(err),
    }
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
    let session = match require_session(&state, &headers).await {
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
        match state.db.pending_device_request(&user_code).await {
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
    let session = match require_session(&state, &headers).await {
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
        let grants = match session.grants(&state.db).await {
            Ok(grants) => grants,
            Err(err) => return internal(err),
        };
        match state
            .db
            .approve_device(&form.user_code, session.principal(), &grants)
            .await
        {
            Ok(true) => "Approved. Return to your terminal — the CLI will continue.",
            Ok(false) => "That code is unknown, already resolved, or expired.",
            Err(err) => return internal(err),
        }
    } else {
        match state.db.deny_device(&form.user_code).await {
            Ok(_) => "Denied.",
            Err(err) => return internal(err),
        }
    };
    Redirect::to(&format!("/activate?message={}", urlencode(message))).into_response()
}

// -- orgs -------------------------------------------------------------------

// -- create organization ----------------------------------------------------

// -- create project / binding / registry under an org -----------------------

/// Gate a mutation on `perm` at an org `scope`: `403` for a member who lacks
/// it, `404` for a non-member (existence undisclosed), `None` when allowed.
///
/// The shared authz shape for the org-scoped create/delete handlers, matching
/// the `404`-private / `403`-forbidden discipline the read pages use.
async fn require_org_perm(
    state: &AppState,
    session: &Session,
    scope: &Scope,
    perm: Permission,
) -> Option<Box<Response>> {
    if session.allows(&state.db, perm, scope).await {
        return None;
    }
    if session.allows(&state.db, Permission::Read, scope).await {
        Some(Box::new(
            (StatusCode::FORBIDDEN, "insufficient permission").into_response(),
        ))
    } else {
        Some(Box::new(StatusCode::NOT_FOUND.into_response()))
    }
}

// -- registry settings / management landing ---------------------------------

/// Render the registry settings landing page, optionally echoing a
/// just-applied visibility change-set id.
///
/// `RegistryConfigure`-gated: a member without it gets `403`, a non-member of a
/// private registry's org gets `404`.
async fn registry_settings_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<&str>,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    if let Some(deny) =
        require_org_perm(state, session, &scope, Permission::RegistryConfigure).await
    {
        return *deny;
    }
    let result_outcome = async {
        // Resolve the storage binding (name, root, prefix) when bound.
        let binding = match registry.storage_binding_id {
            Some(id) => state
                .db
                .storage_binding(id)
                .await?
                .map(|b| (b.name, b.root, registry.prefix.clone())),
            None => None,
        };
        // Deletion is owner-only (the iam.admin verb).
        let can_delete = session
            .allows(&state.db, Permission::IamAdmin, &scope)
            .await;
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

/// The visibility-change action: CSRF + `RegistryConfigure` gate, then route
/// the flip through the audited change-set engine and re-render the settings
/// page with the new change id.
async fn registry_visibility_action(
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
    if let Some(deny) =
        require_org_perm(state, session, &scope, Permission::RegistryConfigure).await
    {
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
    )
    .await
    {
        Ok(id) => id,
        Err(err) => return internal(err),
    };
    // Re-read so the page shows the new visibility.
    let updated = match state.db.registry_by_slug(&registry.slug).await {
        Ok(Some(reg)) => reg,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return internal(err),
    };
    registry_settings_view(state, session, &updated, Some(change_id.0.as_str())).await
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
async fn registry_delete_action(
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
    if let Some(deny) = require_org_perm(state, session, &scope, Permission::IamAdmin).await {
        return *deny;
    }
    if confirm.trim() != registry.slug {
        return (StatusCode::BAD_REQUEST, "type the registry name to confirm").into_response();
    }
    let result = async {
        let removed = state.db.delete_registry(registry.id).await?;
        if removed {
            state
                .db
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
        // Redirect to the owning org's dashboard when known.
        let target = match registry.org_id {
            Some(org_id) => match state.db.org_by_id(org_id).await? {
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
    let registry = match resolve_by_prefix(state, left.trim_end_matches('/')).await {
        Ok(Some((reg, tail))) if tail.is_empty() => reg,
        Ok(_) => return None,
        Err(err) => return Some(internal(err)),
    };

    // Console pages are human-only: require a session now that the path is
    // known to be a console page.
    let session = match require_session(state, headers).await {
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
        ("settings/tokens", false) => {
            tokens_view(state, &session, &registry, headers, page_number).await
        }
        ("settings/tokens", true) => {
            tokens_create_action(
                state,
                &session,
                &registry,
                field(&fields, "csrf"),
                fields.contains_key("perm_read"),
                fields.contains_key("perm_publish"),
            )
            .await
        }
        ("settings/tokens/revoke", true) => {
            tokens_modify_action(
                state,
                &session,
                &registry,
                field(&fields, "csrf"),
                field(&fields, "token_id"),
                false,
            )
            .await
        }
        ("settings/tokens/rotate", true) => {
            tokens_modify_action(
                state,
                &session,
                &registry,
                field(&fields, "csrf"),
                field(&fields, "token_id"),
                true,
            )
            .await
        }
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
        ("settings/serving", false) => serving_view(state, &session, &registry, None).await,
        ("settings/serving", true) => serving_action(state, &session, &registry, &fields).await,
        ("settings", false) => registry_settings_view(state, &session, &registry, None).await,
        ("settings/visibility", true) => {
            registry_visibility_action(
                state,
                &session,
                &registry,
                field(&fields, "csrf"),
                field(&fields, "visibility"),
            )
            .await
        }
        ("settings/delete", true) => {
            registry_delete_action(
                state,
                &session,
                &registry,
                field(&fields, "csrf"),
                field(&fields, "confirm"),
            )
            .await
        }
        ("changes", false) => changes_view(state, &session, &registry).await,
        ("keys", false) => keys_view(state, &session, &registry, headers, page_number).await,
        ("keys/rotate", false) => keys_rotate_view(state, &session, &registry, headers).await,
        ("publishes", false) => publishes_view(state, &session, &registry, headers).await,
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
                if let Err(deny) = authorize_registry_read(state, &registry, headers).await {
                    return Some(*deny);
                }
                render_channel_console(state, &session, &registry, &name, None, None).await
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
async fn resolve_registry(
    state: &AppState,
    slug: &str,
    uri: &axum::http::Uri,
) -> anyhow::Result<Option<RegistryRecord>> {
    if let Some(reg) = state.db.registry_by_slug(slug).await? {
        return Ok(Some(reg));
    }
    // Nested: strip the trailing `/-/...` marker and resolve by prefix.
    let path = uri.path().trim_start_matches('/');
    let head = path.split("/-/").next().unwrap_or(path);
    match resolve_by_prefix(state, head.trim_end_matches('/')).await? {
        Some((reg, _)) => Ok(Some(reg)),
        None => Ok(None),
    }
}

// -- registry tokens --------------------------------------------------------

/// Render the tokens page (read path): visibility-gated, no result banner.
async fn tokens_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
    page_number: usize,
) -> Response {
    // Reads follow registry visibility (404 a hidden registry).
    if let Err(deny) = authorize_registry_read(state, registry, headers).await {
        return *deny;
    }
    render_tokens(state, session, registry, None, page_number).await
}

/// The token-create action: CSRF + TokensSelf gate, mint, show secret once.
async fn tokens_create_action(
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
    if !session
        .allows(&state.db, Permission::TokensSelf, &scope)
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
    // A token may never exceed the owner's own grants: keep only requested
    // permissions the user actually holds at the scope.
    let grants = match session.grants(&state.db).await {
        Ok(grants) => grants,
        Err(err) => return internal(err),
    };
    perms.retain(|p| iam::allow(&grants, *p, &scope));
    let (_, secret) = match state
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
        state,
        session,
        registry,
        Some(("New token created", &secret)),
        1,
    )
    .await
}

/// The token revoke/rotate action: CSRF + ownership gate, then mutate.
///
/// `rotate = true` rotates (showing the new secret once); `false` revokes.
async fn tokens_modify_action(
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
    if let Err(resp) = ensure_owns_token(state, session, token_id).await {
        return *resp;
    }
    // Rotation mints a fresh secret (a new credential), so it gates on sudo;
    // revocation only deadens a credential and does not (M-1).
    if rotate {
        if let Err(resp) = require_sudo(session) {
            return *resp;
        }
        match state.db.rotate_token(token_id).await {
            Ok(Some((_, secret))) => {
                render_tokens(
                    state,
                    session,
                    registry,
                    Some(("Token rotated", &secret)),
                    1,
                )
                .await
            }
            Ok(None) => {
                Redirect::to(&format!("/{}/-/settings/tokens", registry.slug)).into_response()
            }
            Err(err) => internal(err),
        }
    } else {
        match state.db.revoke_token(token_id).await {
            Ok(()) => {
                Redirect::to(&format!("/{}/-/settings/tokens", registry.slug)).into_response()
            }
            Err(err) => internal(err),
        }
    }
}

/// Render the tokens page, optionally with a one-time secret result.
async fn render_tokens(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    result: Option<(&str, &str)>,
    page_number: usize,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    let can_create = session
        .allows(&state.db, Permission::TokensSelf, &scope)
        .await;
    // List the caller's own tokens; filter to this registry scope.
    let all = match state.db.list_tokens_for(session.principal()).await {
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

/// Verify the session user owns the token being revoked/rotated, else 403.
async fn ensure_owns_token(
    state: &AppState,
    session: &Session,
    token_id: &str,
) -> Result<(), Box<Response>> {
    let owned = state
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

/// Render the channel console.
///
/// `prepared` carries a BYO-key prepared operation (`(change_id, command)`) to
/// echo; `advanced` carries a hosted-key direct-advance success message. The
/// page renders a real (hosted-key) advance form when the registry has a
/// hosted key bound, and the prepared-operation form otherwise.
async fn render_channel_console(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    name: &str,
    prepared: Option<(&str, &str)>,
    advanced: Option<&str>,
) -> Response {
    let result = async {
        let status = state.db.index_status(registry.id).await?;
        let channels = state.db.list_channels(registry.id).await?;
        let Some(channel) = channels.into_iter().find(|c| c.name == name) else {
            return Ok(None);
        };
        let scope = Scope::parse(&registry.slug);
        let can_advance = session
            .allows(&state.db, Permission::ChannelAdvance, &scope)
            .await;
        let hosted_key = match registry.hosted_key_id {
            Some(id) => state.db.hosted_key(id).await?.map(|k| k.key_id),
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
    if !session
        .allows(&state.db, Permission::ChannelAdvance, &scope)
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
        &state.db,
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
    if !session
        .allows(&state.db, Permission::ChannelAdvance, &scope)
        .await
    {
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
            render_channel_console(state, session, registry, name, None, Some(&message)).await
        }
        Err(err) => {
            // A failed advance (e.g. unknown release, below floor) is a
            // client/operator error, not an internal fault: surface the cause.
            (StatusCode::BAD_REQUEST, format!("advance failed: {err:#}")).into_response()
        }
    }
}

// -- hosted signing keys ----------------------------------------------------

// -- webhooks ---------------------------------------------------------------

// -- single sign-on (OIDC IdP + email domains) ------------------------------

// -- serving frontends + mirror ---------------------------------------------

/// Render the serving & mirror page; `RegistryConfigure`-gated at the registry
/// scope (a reader without it gets 403, a non-member 404 via visibility).
async fn serving_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    notice: Option<&str>,
) -> Response {
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&state.db, Permission::RegistryConfigure, &scope)
        .await
    {
        if let Err(deny) = authorize_registry_read(state, registry, &HeaderMap::new()).await {
            return *deny;
        }
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    let result = async {
        let frontends = state.db.list_frontends(registry.id).await?;
        let mirror = state.db.mirror_source(registry.id).await?;
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

/// Apply a serving/mirror mutation. Shared by the flat route and the
/// nested-canonical [`dispatch_nested`] path; `RegistryConfigure`-gated and
/// CSRF-checked; every op is audited.
async fn serving_action(
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
    if !session
        .allows(&state.db, Permission::RegistryConfigure, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "registry.configure required").into_response();
    }
    async fn audit(
        state: &AppState,
        session: &Session,
        registry: &RegistryRecord,
        action: &str,
        detail: &str,
    ) -> anyhow::Result<i64> {
        state
            .db
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
            // create_frontend validates the mode and rejects unsafe domains.
            let created = state
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
            if let Err(err) = audit(state, session, registry, "frontend.add", domain).await {
                return internal(err);
            }
            serving_view(state, session, registry, Some("Frontend added.")).await
        }
        "delete-frontend" => {
            let Ok(id) = field("id").parse::<i64>() else {
                return (StatusCode::BAD_REQUEST, "bad frontend id").into_response();
            };
            // The frontend must belong to this registry.
            match state.db.list_frontends(registry.id).await {
                Ok(list) if list.iter().any(|f| f.id == id) => {}
                Ok(_) => return (StatusCode::NOT_FOUND, "no such frontend").into_response(),
                Err(err) => return internal(err),
            }
            if let Err(err) = state.db.delete_frontend(id).await {
                return internal(err);
            }
            if let Err(err) =
                audit(state, session, registry, "frontend.delete", &id.to_string()).await
            {
                return internal(err);
            }
            serving_view(state, session, registry, Some("Frontend deleted.")).await
        }
        "set-mirror" => {
            let upstream = field("upstream_url").trim();
            if upstream.is_empty() {
                return (StatusCode::BAD_REQUEST, "upstream URL is required").into_response();
            }
            let secs: i64 = field("schedule_secs").trim().parse().unwrap_or(3600);
            // create_mirror_source validates the mode and rejects SSRF targets.
            let r = state
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
            if let Err(err) = audit(state, session, registry, "mirror.set", upstream).await {
                return internal(err);
            }
            serving_view(
                state,
                session,
                registry,
                Some("Mirror configuration saved."),
            )
            .await
        }
        "remove-mirror" => {
            if let Err(err) = state.db.delete_mirror_source(registry.id).await {
                return internal(err);
            }
            if let Err(err) = audit(state, session, registry, "mirror.remove", &registry.slug).await
            {
                return internal(err);
            }
            serving_view(state, session, registry, Some("Stopped mirroring.")).await
        }
        _ => (StatusCode::BAD_REQUEST, "unknown operation").into_response(),
    }
}

// -- keys -------------------------------------------------------------------

/// Render the key roster page: visibility-gated, KeysManage reveals the
/// rotation wizard link.
async fn keys_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
    page_number: usize,
) -> Response {
    if let Err(deny) = authorize_registry_read(state, registry, headers).await {
        return *deny;
    }
    let roster = match state.db.list_roster(registry.id).await {
        Ok(roster) => roster,
        Err(err) => return internal(err),
    };
    let can_manage = session
        .allows(
            &state.db,
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

/// Render the rotation wizard: visibility-gated.
async fn keys_rotate_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Response {
    if let Err(deny) = authorize_registry_read(state, registry, headers).await {
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

/// Render the publish-pipeline view: visibility-gated.
async fn publishes_view(
    state: &AppState,
    session: &Session,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Response {
    if let Err(deny) = authorize_registry_read(state, registry, headers).await {
        return *deny;
    }
    let result = async {
        let status = state.db.index_status(registry.id).await?;
        let releases = state.db.list_releases(registry.id).await?;
        // Recent publish/index activity, filtered to this registry scope.
        let audit: Vec<_> = state
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
    let session = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri).await {
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
    let can_edit = session
        .allows(&state.db, Permission::RegistryConfigure, &scope)
        .await;
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
        .index_status(registry.id)
        .await?
        .and_then(|s| s.last_indexed_commit)
    else {
        return Ok(String::new());
    };
    let head = crate::surface::object::Oid::from_hex(&head_hex)?;
    let fetch = crate::gitwrite::fetcher_for_registry(&state.db, registry).await?;
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
    let session = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri).await {
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
    if !session
        .allows(&state.db, Permission::RegistryConfigure, &scope)
        .await
    {
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
    let session = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Some(registry) = (match resolve_registry(&state, &slug, &uri).await {
        Ok(reg) => reg,
        Err(err) => return internal(err),
    }) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    changes_view(&state, &session, &registry).await
}

/// Render the change-request list page for a resolved registry.
///
/// Gated to `audit.read` (admin+). Each draft renders its file diffs (computed
/// from the recorded old/new file contents) and the promotion command.
async fn changes_view(state: &AppState, session: &Session, registry: &RegistryRecord) -> Response {
    let scope = Scope::parse(&registry.slug);
    if !session
        .allows(&state.db, Permission::AuditRead, &scope)
        .await
    {
        return (StatusCode::FORBIDDEN, "audit.read required").into_response();
    }

    let result = async {
        let merge_url = format!(
            "{}/{}",
            state.external_url.trim_end_matches('/'),
            registry.slug
        );
        let changesets = state.db.list_changesets(&registry.slug).await?;
        let mut requests: Vec<console::ChangeRequestView> = Vec::new();
        for cs in changesets.into_iter().filter(|cs| cs.git_ref.is_some()) {
            let file_diffs = state
                .db
                .list_revisions(&cs.change_id)
                .await
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
            let merge_command =
                crate::gitwrite::merge_command(&merge_url, &config::ChangeId(cs.change_id.clone()));
            requests.push(console::ChangeRequestView {
                change_id: cs.change_id,
                status: cs.status,
                summary: cs.summary.unwrap_or_default(),
                actor_label: cs.actor_label,
                git_commit: cs.git_commit.unwrap_or_default(),
                file_diffs,
                merge_command,
            });
        }
        Ok::<_, anyhow::Error>(console::changes_page(
            &session.email,
            registry,
            &requests,
            Instant::now(),
        ))
    }
    .await;
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
