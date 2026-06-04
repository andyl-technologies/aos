//! ConnectRPC implementation of `AuthService`.

use std::sync::Arc;

use connectrpc::{ConnectError, Context, ErrorCode};

use aos_proto::aos::auth::v1::*;

use crate::auth;
use crate::routes::AppState;

/// ConnectRPC auth service backed by the shared `AppState`.
pub struct AuthServiceImpl {
    pub state: Arc<AppState>,
}

impl AuthService for AuthServiceImpl {
    async fn get_token(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<TokenRequestView<'static>>,
    ) -> Result<(TokenResponse, Context), ConnectError> {
        let provisioning_token: &str = req.provisioning_token;

        // Validate the provisioning secret against the token store.
        let token_record = self
            .state
            .tokens
            .validate_token(provisioning_token)
            .map_err(|e| {
                ConnectError::new(ErrorCode::Internal, format!("token validation error: {e}"))
            })?
            .ok_or_else(|| {
                ConnectError::new(ErrorCode::Unauthenticated, "invalid provisioning secret")
            })?;

        let ttl = self.state.config.oauth2.access_token_ttl;

        let access_token = auth::create_access_token(&self.state.jwt_secret, &token_record, ttl)
            .map_err(|e| {
                ConnectError::new(ErrorCode::Internal, format!("token creation error: {e}"))
            })?;

        let scope = token_record.permissions.join(" ");

        Ok((
            TokenResponse {
                access_token,
                token_type: "Bearer".into(),
                expires_in: ttl,
                scope,
                ..Default::default()
            },
            ctx,
        ))
    }
}
