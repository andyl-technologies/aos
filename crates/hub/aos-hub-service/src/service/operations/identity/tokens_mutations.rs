//! Tokens mutations in the identity capability.

use super::*;

impl RpcService {
    /// Validates an API-token secret, read-through cached in KV when one is
    /// attached, with **revocation safety via a tombstone** (RFC-0004 ch.14
    /// Phase C, `tok:{hash}` + `tokrev:{token_id}`).
    ///
    /// Token auth runs on every API request; this serves the validated
    /// [`TokenAuth`](aos_hub_db::db::TokenAuth) from KV (sub-ms, off the database session
    /// cost) for [`HOT_TTL_SECS`](crate::cache::HOT_TTL_SECS), and skips the
    /// `last_used_at` write `validate_token` performs on a cache hit.
    ///
    /// Because the cache is keyed by the token **secret** but revocation is by
    /// token **id**, a naive TTL cache could serve a revoked token until the TTL.
    /// Instead, [`RpcService::invalidate_token_cache`] writes a `tokrev:{token_id}` tombstone
    /// on revoke/rotate, and this method **rejects any cached resolution whose
    /// token id is tombstoned** — so a revoke is observed immediately, not after
    /// the TTL. (After the resolution TTL the entry re-validates from the
    /// database, which already excludes revoked/rotated tokens.)
    ///
    /// With no `kv` attached this is exactly
    /// [`validate_token`](aos_hub_db::db::Database::validate_token).
    ///
    /// # Errors
    ///
    /// Returns an error on a KV read or database failure.
    pub async fn validate_token_cached(
        &self,
        secret: &str,
    ) -> anyhow::Result<Option<aos_hub_db::db::TokenAuth>> {
        let Some(kv) = &self.kv else {
            return self.db.validate_token(secret).await;
        };
        let key = format!("tok:{}", aos_hub_model::auth::token::sha256_hex(secret));
        let db = &self.db;
        let cached: Option<aos_hub_db::db::TokenAuth> = crate::cache::read_through(
            kv.as_ref(),
            &key,
            Some(crate::cache::HOT_TTL_SECS),
            || async move { db.validate_token(secret).await },
        )
        .await?;
        // Reject a cached resolution whose token was revoked/rotated since it was
        // cached (the tombstone written by `invalidate_token_cache`).
        if let Some(auth) = &cached {
            let tomb = format!("tokrev:{}", auth.token_id);
            if kv.get(&tomb).await?.is_some() {
                return Ok(None);
            }
            if !self
                .db
                .principal_is_live(auth.owner.kind.as_str(), auth.owner.id)
                .await?
            {
                return Ok(None);
            }
        }
        Ok(cached)
    }

    /// Applies one reviewed access-token issuance plan exactly once.
    pub async fn apply_issue_access_token(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::AccessTokenResponse, RpcError> {
        const PLAN_KIND: &str = "issue_access_token";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::TokensManage)
            .await?;
        if let Some(response) = self
            .replayed_control_result::<pb::AccessTokenResponse>(
                auth,
                &req.plan_id,
                PLAN_KIND,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            if response.secret.is_empty() {
                return Err(RpcError::FailedPrecondition(
                    "access token secret was delivered once and cannot be replayed; retire the token if delivery was interrupted"
                        .to_string(),
                ));
            }
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            PLAN_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, AccessTokenIssuePlanInput) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        let scope = parse_authorization_scope(&input.scope)?;
        self.require_permission(&claims, Permission::TokensManage, &scope)
            .await?;
        let owner_id = self
            .resolve_existing_principal_id(&input.owner_kind, &input.owner_ref)
            .await?;
        if owner_id != input.owner_id {
            return Err(RpcError::FailedPrecondition(
                "token owner changed after planning".into(),
            ));
        }
        let owner = match input.owner_kind.as_str() {
            "user" => aos_hub_model::domain::Principal::user(owner_id),
            "service_account" => aos_hub_model::domain::Principal::service_account(owner_id),
            other => return Err(RpcError::invalid(format!("unknown owner kind '{other}'"))),
        };
        let permissions = input
            .permissions
            .iter()
            .map(|verb| {
                Permission::parse(verb)
                    .ok_or_else(|| RpcError::invalid(format!("unknown permission '{verb}'")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let owner_grants = self
            .db
            .effective_scopes(owner)
            .await
            .map_err(RpcError::internal)?;
        let context = self
            .db
            .authorization_context(scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("authorization scope"))?;
        if permissions
            .iter()
            .any(|permission| !iam::allow(&owner_grants, *permission, &context))
        {
            return Err(RpcError::FailedPrecondition(
                "token-owner authority changed after planning".into(),
            ));
        }
        let expires_at =
            (input.ttl_secs > 0).then_some(clock::now_unix_secs().saturating_add(input.ttl_secs));
        let (token_id, secret) = self
            .db
            .create_token(
                owner,
                &input.scope,
                &permissions,
                input.comment.as_deref(),
                expires_at,
            )
            .await
            .map_err(RpcError::internal)?;
        let response = pb::AccessTokenResponse { token_id, secret };
        let persisted = pb::AccessTokenResponse {
            token_id: response.token_id.clone(),
            secret: String::new(),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &persisted)
            .await?;
        Ok(response)
    }

    /// Applies one reviewed access-token retirement plan exactly once.
    pub async fn apply_retire_access_token(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::AccessTokenRetirementResponse, RpcError> {
        const PLAN_KIND: &str = "retire_access_token";
        self.require_control_plan_permission(auth, &req.plan_id, Permission::TokensManage)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                PLAN_KIND,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            PLAN_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, AccessTokenRetirementPlanInput) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        if self
            .db
            .token_lifecycle_version(&input.token_id)
            .await
            .map_err(RpcError::internal)?
            .as_deref()
            != Some("active")
        {
            return Err(RpcError::FailedPrecondition(
                "access token changed after planning".into(),
            ));
        }
        self.db
            .revoke_token(&input.token_id)
            .await
            .map_err(RpcError::internal)?;
        let response = pb::AccessTokenRetirementResponse {};
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
