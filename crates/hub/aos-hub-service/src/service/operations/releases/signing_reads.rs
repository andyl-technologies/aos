//! Signing reads in the releases capability.

use super::*;

impl RpcService {
    /// Lists signing-key identities owned by one exact authorization scope.
    pub async fn list_signing_keys(
        &self,
        auth: Option<&str>,
        req: pb::ListSigningKeysRequest,
    ) -> Result<pb::ListSigningKeysResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &scope)
            .await?;
        let keys = self
            .db
            .list_signing_keys(scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(signing_key_message)
            .collect();
        let (signing_keys, next_page_token) = paginate(keys, req.page_size, &req.page_token)?;
        Ok(pb::ListSigningKeysResponse {
            signing_keys,
            next_page_token,
        })
    }

    /// Reads one signing-key identity and its latest immutable generation.
    pub async fn get_signing_key(
        &self,
        auth: Option<&str>,
        req: pb::GetSigningKeyRequest,
    ) -> Result<pb::SigningKeyResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &scope)
            .await?;
        let key = self
            .db
            .signing_key(scope.as_str(), req.name.trim())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signing key"))?;
        Ok(pb::SigningKeyResponse {
            signing_key: Some(signing_key_message(key)),
        })
    }

    /// Reads one typed consumer pin to an immutable signing-key generation.
    pub async fn get_signing_key_usage(
        &self,
        auth: Option<&str>,
        req: pb::GetSigningKeyUsageRequest,
    ) -> Result<pb::SigningKeyUsageResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        validate_signing_usage_identity(&req.consumer_stable_id, &req.purpose)?;
        let consumer = self
            .db
            .resolve_signing_key_consumer(&req.consumer_stable_id, &req.purpose)
            .await
            .map_err(|error| RpcError::invalid(format!("invalid signing consumer: {error:#}")))?;
        let consumer_scope = parse_authorization_scope(&consumer.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &consumer_scope)
            .await?;
        let usage = self
            .db
            .signing_key_usage(&req.consumer_stable_id, &req.purpose)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signing-key usage"))?;

        Ok(pb::SigningKeyUsageResponse {
            usage: Some(signing_key_usage_message(usage)),
        })
    }
}
