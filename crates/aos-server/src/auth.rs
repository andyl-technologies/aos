//! JWT authentication and the OAuth2-style token exchange endpoint.
//!
//! Authentication is two-tiered:
//!
//! 1. Clients hold a long-lived **provisioning token** (created over the
//!    bootstrap socket, persisted by [`crate::tokens::TokenStore`]).
//! 2. They exchange it at `POST /oauth2/token`
//!    ([`oauth2_token_handler`]) for a short-lived **HS256 JWT** carrying
//!    the authorized views and permissions as [`Claims`].
//!
//! Handlers consume the JWT through two axum extractors:
//!
//! - [`AuthClaims`] — requires a valid `Authorization: Bearer` JWT,
//!   rejecting with `401` otherwise. Used by mutating endpoints (upload,
//!   build, gc).
//! - [`AuthResult`] — allows requests without credentials to proceed as
//!   [`AuthResult::Anonymous`], for GET endpoints on views configured with
//!   `anonymous_read = true`. A *present but invalid* token is still
//!   rejected with `401`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::routes::AppState;
use crate::tokens::TokenRecord;

/// JWT claims embedded in access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Token ID (UUID) of the provisioning token the JWT was minted from.
    pub sub: String,
    /// Authorized views. The wildcard entry `"*"` grants every view.
    pub views: HashSet<String>,
    /// Granted permissions, e.g. `["read", "build"]`.
    pub permissions: HashSet<String>,
    /// Issued-at timestamp (Unix seconds).
    pub iat: usize,
    /// Expiry timestamp (Unix seconds).
    pub exp: usize,
}

impl Claims {
    /// Returns `true` if the claims authorize access to the given view,
    /// either by exact name or via the `"*"` wildcard.
    pub fn has_view(&self, view: &str) -> bool {
        self.views.contains(view) || self.views.contains("*")
    }

    /// Returns `true` if the claims include the given permission
    /// (e.g. `"read"`, `"build"`).
    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.contains(perm)
    }
}

/// Creates a signed JWT access token from a validated provisioning token
/// record.
///
/// The token is signed with HS256 using `secret`, copies the record's views
/// and permissions into the claims, and expires `ttl_secs` seconds from now.
///
/// # Errors
///
/// Returns an error if the system clock is before the Unix epoch or JWT
/// encoding fails.
pub fn create_access_token(
    secret: &[u8],
    token_record: &TokenRecord,
    ttl_secs: u64,
) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_secs() as usize;

    let claims = Claims {
        sub: token_record.id.to_string(),
        views: token_record.views.iter().cloned().collect(),
        permissions: token_record.permissions.iter().cloned().collect(),
        iat: now,
        exp: now + ttl_secs as usize,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )?;

    Ok(token)
}

/// Decodes and validates JWT claims from an `Authorization: Bearer ...`
/// header value.
///
/// The token signature is verified with HS256 against `secret` and the
/// `exp` claim is enforced.
///
/// # Errors
///
/// Returns an error if the header does not start with `Bearer `, the
/// signature is invalid, the token is expired, or the claims cannot be
/// deserialized.
pub fn claims_from_bearer_header(auth_header: &str, secret: &[u8]) -> Result<Claims> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .context("Authorization header must start with Bearer")?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .context("invalid token")?;

    Ok(token_data.claims)
}

/// Axum extractor that validates a JWT from the `Authorization: Bearer` header.
///
/// On success the decoded [`Claims`] are available to the handler.
/// On failure a `401 Unauthorized` response is returned.
pub struct AuthClaims(pub Claims);

impl FromRequestParts<Arc<AppState>> for AuthClaims {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "missing Authorization header").into_response()
            })?;

        let claims = claims_from_bearer_header(auth_header, &state.jwt_secret).map_err(|e| {
            tracing::warn!(error = %e, "JWT validation failed");
            (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")).into_response()
        })?;

        Ok(AuthClaims(claims))
    }
}

/// Result of an authentication check that permits anonymous access.
///
/// Used by GET endpoints on views configured with `anonymous_read = true`.
pub enum AuthResult {
    /// Request carried a valid JWT.
    Authenticated(Claims),
    /// No credentials provided (anonymous access).
    Anonymous,
}

impl FromRequestParts<Arc<AppState>> for AuthResult {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // If no Authorization header is present, allow anonymous access.
        let Some(auth_value) = parts.headers.get(header::AUTHORIZATION) else {
            return Ok(AuthResult::Anonymous);
        };

        let auth_str = auth_value.to_str().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "invalid Authorization header encoding",
            )
                .into_response()
        })?;

        let claims = claims_from_bearer_header(auth_str, &state.jwt_secret).map_err(|e| {
            tracing::warn!(error = %e, "JWT validation failed (anonymous-capable endpoint)");
            (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")).into_response()
        })?;

        Ok(AuthResult::Authenticated(claims))
    }
}

/// OAuth2 token-exchange response body.
#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
}

/// `POST /oauth2/token` — exchanges a provisioning secret for a JWT access
/// token.
///
/// The caller authenticates with `Authorization: Bearer {provisioning-secret}`
/// (the plaintext returned at token creation, *not* a JWT). On success the
/// response is a `200` JSON body in the OAuth2 token-response shape:
/// `access_token`, `token_type` (`"Bearer"`), `expires_in` (seconds, from
/// `[oauth2] access_token_ttl`), and `scope` (space-joined permissions).
///
/// Responds `401` if the header is missing/malformed or the provisioning
/// secret is unknown, revoked, or expired, and `500` if the token store
/// lookup or JWT creation fails.
pub async fn oauth2_token_handler(
    State(state): State<Arc<AppState>>,
    parts: axum::http::Request<axum::body::Body>,
) -> Response {
    let auth_header = match parts
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h.to_string(),
        None => {
            return (StatusCode::UNAUTHORIZED, "missing Authorization header").into_response();
        }
    };

    let secret = match auth_header.strip_prefix("Bearer ") {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "Authorization header must start with Bearer",
            )
                .into_response();
        }
    };

    // Validate the provisioning secret against the token store.
    let token_record = match state.tokens.validate_token(secret) {
        Ok(Some(record)) => record,
        Ok(None) => {
            tracing::warn!("oauth2 token exchange failed: invalid provisioning secret");
            return (StatusCode::UNAUTHORIZED, "invalid provisioning secret").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "oauth2 token validation error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("token validation error: {e}"),
            )
                .into_response();
        }
    };

    let ttl = state.config.oauth2.access_token_ttl;

    let access_token = match create_access_token(&state.jwt_secret, &token_record, ttl) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, token_id = %token_record.id, "oauth2 token creation error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("token creation error: {e}"),
            )
                .into_response();
        }
    };

    tracing::info!(token_id = %token_record.id, ttl, "access token issued");

    let scope = token_record.permissions.join(" "); // Vec from token store

    Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ttl,
        scope,
    })
    .into_response()
}
