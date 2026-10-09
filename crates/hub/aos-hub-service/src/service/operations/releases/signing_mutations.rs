//! Signing mutations in the releases capability.

use super::*;

impl RpcService {
    /// Applies one reviewed signing-key enrollment exactly once.
    pub async fn apply_enroll_signing_key(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::SigningKeyResponse, RpcError> {
        const KIND: &str = "enroll_signing_key";
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                KIND,
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
            KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, SigningKeyMutationPlanInput) = self
            .load_control_plan(auth, &req.plan_id, KIND, Some(&req.confirmation_hash))
            .await?;
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&input.request.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &scope)
            .await?;
        let existing = self
            .db
            .signing_key(scope.as_str(), &input.request.name)
            .await
            .map_err(RpcError::internal)?;
        let key = if let Some(existing) = existing {
            if existing.resource_version != 1
                || existing.generation != 1
                || existing.public_key != input.request.public_key
                || existing.public_key_fingerprint != input.request.public_key_fingerprint
                || existing.custody != input.request.custody
            {
                return Err(RpcError::FailedPrecondition(
                    "signing-key identity was claimed after planning".into(),
                ));
            }
            existing
        } else {
            self.db
                .enroll_signing_key(
                    scope.as_str(),
                    &input.request.name,
                    &input.request.public_key,
                    &input.request.public_key_fingerprint,
                    &input.request.custody,
                )
                .await
                .map_err(RpcError::internal)?;
            self.db
                .signing_key(scope.as_str(), &input.request.name)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("enrolled key disappeared")))?
        };
        let response = pb::SigningKeyResponse {
            signing_key: Some(signing_key_message(key)),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one reviewed signing-key rotation exactly once.
    pub async fn apply_rotate_signing_key(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::SigningKeyResponse, RpcError> {
        self.apply_signing_key_head_mutation(auth, req, "rotate_signing_key", false)
            .await
    }

    /// Applies one reviewed signing-key retirement exactly once.
    pub async fn apply_retire_signing_key(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::SigningKeyResponse, RpcError> {
        self.apply_signing_key_head_mutation(auth, req, "retire_signing_key", true)
            .await
    }

    /// Applies one reviewed typed signing-key usage exactly once.
    pub async fn apply_set_signing_key_usage(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::SigningKeyUsageResponse, RpcError> {
        const KIND: &str = "set_signing_key_usage";
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                KIND,
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
            KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, SigningKeyUsagePlanInput) = self
            .load_control_plan(auth, &req.plan_id, KIND, Some(&req.confirmation_hash))
            .await?;
        let consumer = self
            .db
            .resolve_signing_key_consumer(&input.request.consumer_stable_id, &input.request.purpose)
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!(
                    "signing consumer changed or disappeared after planning: {error:#}"
                ))
            })?;
        if consumer != input.consumer {
            return Err(RpcError::FailedPrecondition(
                "signing consumer identity or authorization scope changed after planning".into(),
            ));
        }
        let key = self
            .db
            .signing_key_generation(
                &input.request.signing_key_stable_id,
                i64::try_from(input.request.signing_key_generation)
                    .map_err(|_| RpcError::invalid("signing_key_generation is too large"))?,
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signing key"))?;
        if key != input.key {
            return Err(RpcError::FailedPrecondition(
                "signing-key head changed after planning".into(),
            ));
        }
        validate_signing_key_consumer_compatibility(&key, &consumer)?;
        let claims = self.require_claims(auth)?;
        let key_scope = parse_authorization_scope(&key.scope_key)?;
        let consumer_scope = parse_authorization_scope(&consumer.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &key_scope)
            .await?;
        self.require_permission(&claims, Permission::KeysManage, &consumer_scope)
            .await?;
        let current = self
            .db
            .signing_key_usage(&input.request.consumer_stable_id, &input.request.purpose)
            .await
            .map_err(RpcError::internal)?;
        if current != input.baseline {
            let recovered = current.as_ref().is_some_and(|usage| {
                input
                    .baseline
                    .as_ref()
                    .map_or(usage.resource_version == 1, |baseline| {
                        usage.resource_version == baseline.resource_version + 1
                    })
                    && usage.signing_key_id == input.request.signing_key_stable_id
                    && u64::try_from(usage.signing_key_generation).ok()
                        == Some(input.request.signing_key_generation)
                    && usage.state == input.request.state
                    && usage.consumer_kind == consumer.kind
                    && usage.consumer_scope_key == consumer.scope_key
                    && usage.consumer_name == consumer.name
            });
            if !recovered {
                return Err(RpcError::FailedPrecondition(
                    "signing-key usage changed after planning".into(),
                ));
            }
        } else {
            self.db
                .set_signing_key_usage(
                    current.as_ref(),
                    &consumer,
                    &input.request.purpose,
                    &input.request.signing_key_stable_id,
                    i64::try_from(input.request.signing_key_generation)
                        .map_err(|_| RpcError::invalid("signing_key_generation is too large"))?,
                    &input.request.state,
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        }
        let usage = self
            .db
            .signing_key_usage(&input.request.consumer_stable_id, &input.request.purpose)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("signing usage disappeared")))?;
        let response = pb::SigningKeyUsageResponse {
            usage: Some(signing_key_usage_message(usage)),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
