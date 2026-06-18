//! Axum extractors and middleware that gate requests.
//!
//! This is the request-time edge of authentication: it turns the raw
//! `Authorization` header or session cookie into a typed, already-verified
//! identity a handler can trust, and bridges that identity into the pure
//! [`crate::domain::iam`] decision function.
//!
//! - [`BearerAuth`] requires a valid HS256 JWT in `Authorization: Bearer`
//!   (machine plane); a missing or invalid token is a `401`.
//! - [`SessionAuth`] requires a valid `__Host-aos_session` cookie (human
//!   plane); [`MaybeSession`] is its optional sibling for anonymous-capable
//!   pages.
//! - [`oauth2_token_handler`] is the small, self-contained `POST
//!   /oauth2/token` exchange: present a provisioning secret in
//!   `Authorization: Bearer`, receive a short-TTL JWT. [`oauth2_router`]
//!   returns it as a mergeable `Router` fragment so the full router
//!   (phase 2c/2d) can mount it.
//!
//! # Two authorization paths
//!
//! Tokens and sessions reach an `allow`-style decision differently:
//!
//! - A **JWT** carries explicit permission verbs and a single bound scope,
//!   so [`token_allows`] decides locally —
//!   `claims.scope contains target && claims.perms contains perm` — with no
//!   database read. On the machine plane the JWT's short TTL (not a live
//!   membership re-check) is the revocation bound: a role revoked at the
//!   membership level stops minting new JWTs at `/oauth2/token` at once
//!   (a hard token revoke is immediate), but an already-issued JWT keeps
//!   its grant until it expires. The RPC and session planes *do* re-check
//!   live memberships per request via [`require_permission`].
//! - A **session** carries only the user id, so the gate loads the user's
//!   current effective scopes from [`crate::db::Database::effective_scopes`]
//!   and calls [`crate::domain::iam::allow`] directly — role changes take
//!   effect immediately.

use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Serialize;

use crate::auth::jwt::{Claims, JwtKeys};
use crate::auth::permission_from_str;
use crate::db::{Database, SessionAuth as DbSessionAuth};
use crate::domain::{iam, Permission, Scope};

/// Shared state the auth extractors and the `/oauth2/token` handler need.
///
/// Holds the hub database (for provisioning-token validation and session
/// lookup) and the JWT signing keys, plus the access-token TTL. The full
/// server may either hold an `Arc<AuthState>` directly or compose it; the
/// extractors are written against `Arc<AuthState>` so they are testable in
/// isolation.
pub struct AuthState {
    /// The hub database.
    pub db: Arc<Database>,
    /// The HS256 keys used to mint and verify access tokens.
    pub jwt_keys: JwtKeys,
    /// Lifetime, in seconds, of a minted access token.
    pub access_token_ttl: i64,
    /// Rate limiter the `/oauth2/token` exchange consults (per token id, with
    /// an IP fallback). Shared with [`AppState`](crate::server::AppState).
    pub ratelimit: Arc<crate::ratelimit::RateLimiter>,
    /// Whether `X-Forwarded-For` may be trusted for the per-IP rate-limit key.
    ///
    /// `false` by default (the safe choice for a directly-exposed hub); see
    /// [`AppState::trusted_proxy`](crate::server::AppState) and the
    /// [`crate::ratelimit`] trust model.
    pub trusted_proxy: bool,
}

impl AuthState {
    /// Builds an auth state with a TTL, generating ephemeral JWT keys.
    ///
    /// Convenience for dev mode and tests; production supplies stable keys
    /// via the struct literal so tokens survive a restart.
    #[must_use]
    pub fn new(db: Arc<Database>, access_token_ttl: i64) -> AuthState {
        AuthState {
            db,
            jwt_keys: JwtKeys::random(),
            access_token_ttl,
            ratelimit: Arc::new(crate::ratelimit::RateLimiter::new()),
            trusted_proxy: false,
        }
    }
}

/// A verified JWT identity (machine plane).
///
/// Produced by the [`FromRequestParts`] impl when the request carries a
/// valid `Authorization: Bearer <jwt>`; wraps the decoded [`Claims`].
pub struct BearerAuth(pub Claims);

impl FromRequestParts<Arc<AuthState>> for BearerAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AuthState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "missing Authorization header").into_response()
            })?;
        let token = header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Authorization header must start with Bearer",
            )
                .into_response()
        })?;
        let claims = state.jwt_keys.verify(token).map_err(|e| {
            tracing::warn!(error = %e, "JWT validation failed");
            (StatusCode::UNAUTHORIZED, "invalid token").into_response()
        })?;
        Ok(BearerAuth(claims))
    }
}

/// A verified human session identity (human plane).
///
/// Produced when the request carries a valid `__Host-aos_session` cookie;
/// wraps the [`crate::db::SessionAuth`] loaded (and `last_seen`-bumped) for
/// that secret.
pub struct SessionAuth(pub DbSessionAuth);

impl FromRequestParts<Arc<AuthState>> for SessionAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AuthState>,
    ) -> Result<Self, Self::Rejection> {
        let secret = session_secret_from_cookies(&parts.headers)
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing session cookie").into_response())?;
        match state.db.validate_session(&secret).await {
            Ok(Some(session)) => Ok(SessionAuth(session)),
            Ok(None) => Err((StatusCode::UNAUTHORIZED, "invalid session").into_response()),
            Err(e) => {
                tracing::error!(error = %e, "session validation error");
                Err((StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response())
            }
        }
    }
}

/// An optional human session (anonymous-capable pages).
///
/// Always extracts successfully: `Some` when a valid session cookie is
/// present, `None` when the cookie is absent. A *present but invalid*
/// cookie still yields `None` here (the page may render anonymously); a
/// page that must reject a bad cookie should use [`SessionAuth`] instead.
pub struct MaybeSession(pub Option<DbSessionAuth>);

impl FromRequestParts<Arc<AuthState>> for MaybeSession {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AuthState>,
    ) -> Result<Self, Self::Rejection> {
        let Some(secret) = session_secret_from_cookies(&parts.headers) else {
            return Ok(MaybeSession(None));
        };
        match state.db.validate_session(&secret).await {
            Ok(session) => Ok(MaybeSession(session)),
            Err(e) => {
                tracing::error!(error = %e, "session validation error");
                Ok(MaybeSession(None))
            }
        }
    }
}

/// Decides whether a JWT's claims authorize `perm` on `target`.
///
/// Local, database-free check: the token must be bound to a scope that
/// *contains* `target` and must carry `perm` explicitly. Unknown permission
/// strings in the claims are ignored. This is the JWT half of the two
/// authorization paths; the session half goes through
/// [`session_allows`].
#[must_use]
pub fn token_allows(claims: &Claims, perm: Permission, target: &Scope) -> bool {
    let scope = Scope::parse(&claims.scope);
    if !scope.contains(target) {
        return false;
    }
    claims
        .perms
        .iter()
        .filter_map(|p| permission_from_str(p))
        .any(|p| p == perm)
}

/// Decides whether a session's user may perform `perm` on `target`.
///
/// Loads the user's *current* effective grants and delegates to
/// [`crate::domain::iam::allow`], so a revoked role denies immediately.
///
/// # Errors
///
/// Returns an error on database failure while loading the user's grants.
pub async fn session_allows(
    db: &Database,
    session: &DbSessionAuth,
    perm: Permission,
    target: &Scope,
) -> anyhow::Result<bool> {
    let grants = db
        .effective_scopes(crate::domain::Principal::user(session.user_id))
        .await?;
    Ok(iam::allow(&grants, perm, target))
}

/// Requires that a JWT's claims authorize `perm` on `target`, else `403`.
///
/// The bearer/JWT bridge to [`crate::domain::iam`]: returns `Ok(())` when
/// [`token_allows`] is satisfied and a `403 Forbidden` response otherwise.
///
/// # Errors
///
/// Returns a boxed `403 Forbidden` [`Response`] when the claims do not
/// authorize the action. The `Err` is boxed to keep the `Ok` path small.
pub fn require_permission(
    claims: &Claims,
    perm: Permission,
    target: &Scope,
) -> Result<(), Box<Response>> {
    if token_allows(claims, perm, target) {
        Ok(())
    } else {
        Err(Box::new(
            (StatusCode::FORBIDDEN, "insufficient permission").into_response(),
        ))
    }
}

// The CSRF synchronizer-token primitives moved to the wasm-clean
// `aos_hub_core::web::csrf` (RFC-0004 Phase 5, console-dedup stage A) so
// the Worker shares them; re-exported here so every
// `crate::auth::extract::{connect_or_csrf_ok, mint_csrf_token,
// verify_csrf_token}` call site is unchanged.
pub use aos_hub_core::web::csrf::{connect_or_csrf_ok, mint_csrf_token, verify_csrf_token};

/// Extracts the `__Host-aos_session` value from a request's `Cookie` header.
fn session_secret_from_cookies(headers: &HeaderMap) -> Option<String> {
    aos_hub_core::web::session::session_secret_from_headers(headers)
}

/// OAuth2 token-exchange response body.
#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
}

/// Returns a `Router` mounting `POST /oauth2/token`.
///
/// A mergeable fragment so the full hub router (phase 2c/2d) can compose
/// the exchange endpoint without this module reaching into `server.rs`.
pub fn oauth2_router() -> Router<Arc<AuthState>> {
    Router::new().route("/oauth2/token", post(oauth2_token_handler))
}

/// `POST /oauth2/token` — exchanges a provisioning secret for a JWT.
///
/// The caller authenticates with `Authorization: Bearer <provisioning
/// secret>` (the `aos_`-prefixed plaintext, *not* a JWT). On success the
/// response is a `200` JSON body — `access_token`, `token_type`
/// (`"Bearer"`), and `expires_in` (seconds). Responds `401` when the header
/// is missing/malformed or the secret is unknown, revoked (past grace), or
/// expired, and `500` on a token-store or JWT-minting failure.
pub async fn oauth2_token_handler(State(state): State<Arc<AuthState>>, parts: Parts) -> Response {
    // Rate-limit the exchange per source IP to bound credential spray (an
    // attacker probing provisioning secrets). The key is the real TCP peer
    // unless the deployment trusts its proxy's `X-Forwarded-For`, so a forged
    // header cannot evade the limit. See [`crate::ratelimit`].
    let peer = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map_or_else(String::new, |ci| ci.0.ip().to_string());
    let xff = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let ip = crate::ratelimit::client_ip(xff, &peer, state.trusted_proxy);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let crate::ratelimit::RateDecision::Limited { retry_after } =
        state
            .ratelimit
            .check(crate::ratelimit::RateClass::TokenExchange, &ip, now)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.max(1).to_string())],
            "rate limit exceeded",
        )
            .into_response();
    }
    let header = match parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return (StatusCode::UNAUTHORIZED, "missing Authorization header").into_response(),
    };
    let secret = match header.strip_prefix("Bearer ") {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "Authorization header must start with Bearer",
            )
                .into_response()
        }
    };
    let auth = match state.db.validate_token(secret).await {
        Ok(Some(auth)) => auth,
        Ok(None) => {
            tracing::warn!("oauth2 exchange failed: invalid provisioning secret");
            return (StatusCode::UNAUTHORIZED, "invalid provisioning secret").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "oauth2 token validation error");
            return (StatusCode::INTERNAL_SERVER_ERROR, "token validation error").into_response();
        }
    };
    match state.jwt_keys.mint(&auth, state.access_token_ttl) {
        Ok(access_token) => {
            tracing::info!(token_id = %auth.token_id, "access token issued");
            Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: state.access_token_ttl,
            })
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, token_id = %auth.token_id, "oauth2 minting error");
            (StatusCode::INTERNAL_SERVER_ERROR, "token creation error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_allows_scope_and_perm_matrix() {
        let claims = Claims {
            sub: "t".into(),
            owner_kind: "user".into(),
            owner_id: 1,
            scope: "acme/infra".into(),
            perms: vec!["read".into(), "publish".into()],
            iat: 0,
            exp: 0,
        };
        // Permission held, target under the token scope: allowed.
        assert!(token_allows(
            &claims,
            Permission::Read,
            &Scope::parse("acme/infra/prod")
        ));
        assert!(token_allows(
            &claims,
            Permission::Publish,
            &Scope::parse("acme/infra")
        ));
        // Permission not held: denied.
        assert!(!token_allows(
            &claims,
            Permission::MembersManage,
            &Scope::parse("acme/infra")
        ));
        // Target outside the token scope: denied.
        assert!(!token_allows(
            &claims,
            Permission::Read,
            &Scope::parse("acme")
        ));
        assert!(!token_allows(
            &claims,
            Permission::Read,
            &Scope::parse("globex/infra")
        ));
    }

    #[tokio::test]
    async fn require_permission_maps_to_403() {
        let claims = Claims {
            sub: "t".into(),
            owner_kind: "user".into(),
            owner_id: 1,
            scope: "acme".into(),
            perms: vec!["read".into()],
            iat: 0,
            exp: 0,
        };
        assert!(require_permission(&claims, Permission::Read, &Scope::parse("acme")).is_ok());
        let err = require_permission(&claims, Permission::Publish, &Scope::parse("acme"));
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn session_allows_uses_current_grants() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("dev@acme.com", None).await.unwrap();
        db.grant_membership("user", user, "acme", "maintainer")
            .await
            .unwrap();
        let session = DbSessionAuth {
            user_id: user,
            auth_level: 0,
            last_authenticated_at: 0,
            expires_at: i64::MAX,
        };
        assert!(session_allows(
            &db,
            &session,
            Permission::Publish,
            &Scope::parse("acme/infra")
        )
        .await
        .unwrap());
        // A maintainer cannot manage members.
        assert!(!session_allows(
            &db,
            &session,
            Permission::MembersManage,
            &Scope::parse("acme")
        )
        .await
        .unwrap());
    }

    #[test]
    fn csrf_token_roundtrips() {
        let token = mint_csrf_token("session-secret");
        assert!(verify_csrf_token("session-secret", &token));
        assert!(!verify_csrf_token("other-secret", &token));
        assert!(!verify_csrf_token("session-secret", "garbage"));
    }

    #[test]
    fn connect_or_csrf_ok_paths() {
        // Connect-protocol header alone passes.
        let mut headers = HeaderMap::new();
        headers.insert("connect-protocol-version", "1".parse().unwrap());
        assert!(connect_or_csrf_ok(&headers, None));

        // Valid synchronizer token passes.
        let secret = "sess";
        let csrf = mint_csrf_token(secret);
        let mut headers = HeaderMap::new();
        headers.insert("x-aos-csrf", csrf.parse().unwrap());
        assert!(connect_or_csrf_ok(&headers, Some(secret)));

        // Neither: blocked.
        assert!(!connect_or_csrf_ok(&HeaderMap::new(), Some(secret)));
        // Wrong token: blocked.
        let mut headers = HeaderMap::new();
        headers.insert("x-aos-csrf", "nope".parse().unwrap());
        assert!(!connect_or_csrf_ok(&headers, Some(secret)));
    }
}
