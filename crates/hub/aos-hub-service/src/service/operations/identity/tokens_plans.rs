//! Tokens plans in the identity capability.

use super::*;

impl RpcService {
    /// Persists an immutable plan for issuing a scoped access token.
    pub async fn plan_issue_access_token(
        &self,
        auth: Option<&str>,
        req: pb::PlanIssueAccessTokenRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope)?;
        let context = self
            .db
            .authorization_context(scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("authorization scope"))?;
        self.require_permission(&claims, Permission::TokensManage, &scope)
            .await?;
        if req.ttl_secs < 0 || req.ttl_secs > ACCESS_TOKEN_MAX_TTL_SECS {
            return Err(RpcError::invalid(format!(
                "ttl_secs must be 0 or between 1 and {ACCESS_TOKEN_MAX_TTL_SECS}"
            )));
        }
        let (kind, principal_ref) = req.owner.split_once(':').ok_or_else(|| {
            RpcError::invalid("owner must be 'user:<email>' or 'service_account:<org>/<name>'")
        })?;
        let owner_id = self
            .resolve_existing_principal_id(kind, principal_ref)
            .await?;
        let owner = match kind {
            "user" => aos_hub_model::domain::Principal::user(owner_id),
            "service_account" => aos_hub_model::domain::Principal::service_account(owner_id),
            other => return Err(RpcError::invalid(format!("unknown owner kind '{other}'"))),
        };
        let mut perms = Vec::new();
        for verb in &req.permissions {
            let perm = Permission::parse(verb)
                .ok_or_else(|| RpcError::invalid(format!("unknown permission '{verb}'")))?;
            perms.push(perm);
        }
        // A token can never exceed its owner's authority.
        let grants = self
            .db
            .effective_scopes(owner)
            .await
            .map_err(RpcError::internal)?;
        if perms.is_empty()
            || perms
                .iter()
                .any(|permission| !iam::allow(&grants, *permission, &context))
        {
            return Err(RpcError::PermissionDenied(
                "token permissions exceed the owner's current grants".to_string(),
            ));
        }
        let mut permissions = perms
            .iter()
            .map(|permission| permission.as_str().to_string())
            .collect::<Vec<_>>();
        permissions.sort();
        permissions.dedup();
        let canonical_grants = grants
            .iter()
            .map(|(scope, role)| (scope.as_str(), role.as_str()))
            .collect::<Vec<_>>();
        let grants_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&canonical_grants).map_err(RpcError::internal)?,
        ));
        if !req.expected_resource_version.is_empty()
            && req.expected_resource_version != grants_digest
        {
            return Err(RpcError::FailedPrecondition(
                "token-owner grant revision is stale".into(),
            ));
        }
        let input = AccessTokenIssuePlanInput {
            owner_kind: kind.to_string(),
            owner_ref: principal_ref.to_string(),
            owner_id,
            scope: scope.as_str().to_string(),
            permissions,
            ttl_secs: if req.ttl_secs == 0 {
                ACCESS_TOKEN_DEFAULT_TTL_SECS
            } else {
                req.ttl_secs
            },
            comment: (!req.comment.trim().is_empty()).then(|| req.comment.trim().to_string()),
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "issue_access_token",
            &input.scope,
            &input,
            &req.idempotency_key,
            vec![format!(
                "issue access token for {}:{}",
                input.owner_kind, input.owner_ref
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Persists an immutable plan for retiring one access-token generation.
    pub async fn plan_retire_access_token(
        &self,
        auth: Option<&str>,
        req: pb::PlanRetireAccessTokenRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let (token_scope, current) = self
            .db
            .token_scope_and_lifecycle(&req.token_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("access token"))?;
        self.require_permission(
            &claims,
            Permission::TokensManage,
            &Scope::parse(&token_scope),
        )
        .await?;
        if req.expected_resource_version != current {
            return Err(RpcError::FailedPrecondition(
                "access token resource version is stale".into(),
            ));
        }
        if current != "active" {
            return Err(RpcError::FailedPrecondition(
                "access token is not active".into(),
            ));
        }
        let input = AccessTokenRetirementPlanInput {
            token_id: req.token_id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "retire_access_token",
            &token_scope,
            &input,
            &req.idempotency_key,
            vec![format!("retire access token {}", input.token_id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }
}
