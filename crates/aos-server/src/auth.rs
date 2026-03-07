use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use axum::{
    extract::{FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::routes::AppState;
use crate::tokens::TokenRecord;

/// JWT claims embedded in access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Token ID (UUID).
    pub sub: String,
    /// Authorized views.
    pub views: Vec<String>,
    /// Granted permissions, e.g. `["read", "build"]`.
    pub permissions: Vec<String>,
    /// Issued-at timestamp (Unix seconds).
    pub iat: usize,
    /// Expiry timestamp (Unix seconds).
    pub exp: usize,
}

/// Create a signed JWT access token from a validated provisioning token record.
pub fn create_access_token(
    secret: &[u8],
    token_record: &TokenRecord,
    ttl_secs: u64,
) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as usize;

    let claims = Claims {
        sub: token_record.id.to_string(),
        views: token_record.views.clone(),
        permissions: token_record.permissions.clone(),
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

        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Authorization header must start with Bearer",
            )
                .into_response()
        })?;

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&state.jwt_secret),
            &validation,
        )
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("invalid token: {e}"),
            )
                .into_response()
        })?;

        Ok(AuthClaims(token_data.claims))
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

        let token = auth_str.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Authorization header must start with Bearer",
            )
                .into_response()
        })?;

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&state.jwt_secret),
            &validation,
        )
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("invalid token: {e}"),
            )
                .into_response()
        })?;

        Ok(AuthResult::Authenticated(token_data.claims))
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

/// `POST /oauth2/token` — exchange a provisioning secret for a JWT access token.
///
/// The caller authenticates with `Authorization: Bearer {provisioning-secret}`.
/// On success a short-lived JWT is returned.
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
            return (StatusCode::UNAUTHORIZED, "invalid provisioning secret").into_response();
        }
        Err(e) => {
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("token creation error: {e}"),
            )
                .into_response();
        }
    };

    let scope = token_record.permissions.join(" ");

    Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ttl,
        scope,
    })
    .into_response()
}
