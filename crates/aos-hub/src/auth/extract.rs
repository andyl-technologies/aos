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
//! OAuth device, refresh, and provisioning grants are handled by the shared
//! runtime-neutral router in `aos-hub-core` so native and Worker deployments
//! expose one contract.
//!
//! # Two authorization paths
//!
//! Tokens and sessions reach an `allow`-style decision differently:
//!
//! - A **JWT** carries explicit permission verbs and a single bound scope.
//!   Once the caller loads the target's stable ancestor context,
//!   [`token_allows`] checks that it contains `claims.scope` and that the
//!   claims contain the permission. Every machine-plane authorization then
//!   intersects that claim with the principal's current effective memberships,
//!   so deleting a principal or revoking a role deadens issued JWTs immediately.
//! - A **session** carries only the user id, so the gate loads the user's
//!   current effective scopes from [`crate::db::Database::effective_scopes`]
//!   and calls [`crate::domain::iam::allow`] directly — role changes take
//!   effect immediately.

use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::auth::jwt::{Claims, JwtKeys};
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
pub fn token_allows(claims: &Claims, perm: Permission, target: &iam::AuthorizationContext) -> bool {
    iam::token_allows(claims, perm, target)
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
    let Some(context) = db.authorization_context(target.as_str()).await? else {
        return Ok(false);
    };
    Ok(iam::allow(&grants, perm, &context))
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

#[cfg(test)]
mod tests {
    use super::*;

    const ORG_SCOPE: &str = "org:00000000000000000000000000000001";
    const PROJECT_SCOPE: &str = "project:00000000000000000000000000000001";
    const OTHER_ORG_SCOPE: &str = "org:00000000000000000000000000000002";

    #[test]
    fn token_allows_scope_and_perm_matrix() {
        let claims = Claims {
            sub: "t".into(),
            owner_kind: "user".into(),
            owner_id: 1,
            scope: ORG_SCOPE.into(),
            perms: vec!["read".into(), "publish".into()],
            authz_version: crate::auth::jwt::AUTHORIZATION_CLAIMS_VERSION.into(),
            iat: 0,
            exp: 0,
        };
        let project_context = iam::AuthorizationContext::try_new(
            Scope::parse(PROJECT_SCOPE),
            vec![
                Scope::parse(PROJECT_SCOPE),
                Scope::parse(ORG_SCOPE),
                Scope::root(),
            ],
        )
        .unwrap();
        let org_context = iam::AuthorizationContext::try_new(
            Scope::parse(ORG_SCOPE),
            vec![Scope::parse(ORG_SCOPE), Scope::root()],
        )
        .unwrap();
        let other_context = iam::AuthorizationContext::try_new(
            Scope::parse(OTHER_ORG_SCOPE),
            vec![Scope::parse(OTHER_ORG_SCOPE), Scope::root()],
        )
        .unwrap();
        // Permission held, target under the token scope: allowed.
        assert!(token_allows(&claims, Permission::Read, &project_context));
        assert!(token_allows(&claims, Permission::Publish, &org_context));
        // Permission not held: denied.
        assert!(!token_allows(
            &claims,
            Permission::MembersManage,
            &org_context
        ));
        // Target outside the token scope: denied.
        assert!(!token_allows(&claims, Permission::Read, &other_context));
        assert!(!token_allows(&claims, Permission::Read, &other_context));
    }

    #[tokio::test]
    async fn require_permission_maps_to_403() {
        let claims = Claims {
            sub: "t".into(),
            owner_kind: "user".into(),
            owner_id: 1,
            scope: ORG_SCOPE.into(),
            perms: vec!["read".into()],
            authz_version: crate::auth::jwt::AUTHORIZATION_CLAIMS_VERSION.into(),
            iat: 0,
            exp: 0,
        };
        let context = iam::AuthorizationContext::try_new(
            Scope::parse(ORG_SCOPE),
            vec![Scope::parse(ORG_SCOPE), Scope::root()],
        )
        .unwrap();
        assert!(token_allows(&claims, Permission::Read, &context));
        assert!(!token_allows(&claims, Permission::Publish, &context));
    }

    #[tokio::test]
    async fn session_allows_uses_current_grants() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_org("acme", "Acme").await.unwrap();
        let org = db.org_by_slug("acme").await.unwrap().unwrap();
        db.create_project(org.id, "infra", "Infra").await.unwrap();
        let project = db
            .list_projects(org.id)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let user = db.create_user("dev@acme.com", None).await.unwrap();
        db.grant_membership("user", user, &org.stable_id, "maintainer")
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
            &Scope::parse(&project.scope_key)
        )
        .await
        .unwrap());
        // A maintainer cannot manage members.
        assert!(!session_allows(
            &db,
            &session,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id)
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
