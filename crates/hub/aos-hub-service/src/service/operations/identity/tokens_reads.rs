//! Tokens reads in the identity capability.

use super::*;

impl RpcService {
    /// Lists secret-free token generations at one exact authorization scope.
    ///
    /// # Errors
    ///
    /// [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT;
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_access_tokens(
        &self,
        auth: Option<&str>,
        req: pb::ListAccessTokensRequest,
    ) -> Result<pb::ListAccessTokensResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope)?;
        if self
            .db
            .authorization_context(scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .is_none()
        {
            return Err(RpcError::not_found("authorization scope"));
        }
        self.require_permission(&claims, Permission::TokensManage, &scope)
            .await?;
        let rows = self
            .db
            .list_access_token_metadata(scope.as_str())
            .await
            .map_err(RpcError::internal)?;
        let mut tokens = Vec::with_capacity(rows.len());
        for token in rows {
            let owner_ref = match token.owner_kind.as_str() {
                "user" => self
                    .db
                    .user_email(token.owner_id)
                    .await
                    .map_err(RpcError::internal)?,
                "service_account" => self
                    .db
                    .service_account_reference(token.owner_id)
                    .await
                    .map_err(RpcError::internal)?,
                _ => None,
            }
            .unwrap_or_else(|| format!("deleted:{}", token.owner_id));
            tokens.push(pb::TokenInfo {
                token_id: token.token_id,
                owner: format!("{}:{owner_ref}", token.owner_kind),
                scope: token.scope,
                permissions: token
                    .permissions
                    .iter()
                    .map(|permission| permission.as_str().to_string())
                    .collect(),
                created_at: token.created_at,
                expires_at: token.expires_at.unwrap_or_default(),
                resource_version: token.resource_version,
                comment: token.comment.unwrap_or_default(),
                last_used_at: token.last_used_at.unwrap_or_default(),
                rotated_at: token.rotated_at.unwrap_or_default(),
                retired_at: token.retired_at.unwrap_or_default(),
            });
        }
        let (tokens, next_page_token) = paginate(tokens, req.page_size, &req.page_token)?;
        Ok(pb::ListAccessTokensResponse {
            tokens,
            next_page_token,
        })
    }
}
