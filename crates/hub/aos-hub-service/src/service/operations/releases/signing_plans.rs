//! Signing plans in the releases capability.

use super::*;

impl RpcService {
    /// Plans enrollment of a new externally custodied signing-key generation.
    pub async fn plan_enroll_signing_key(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanSigningKeyMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &scope)
            .await?;
        normalize_signing_key_mutation(&mut req)?;
        require_absent_resource_version(&req.expected_resource_version)?;
        if self
            .db
            .signing_key(scope.as_str(), &req.name)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists("signing key already exists".into()));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = SigningKeyMutationPlanInput {
            request: req,
            baseline: None,
        };
        let confirmation_hash = control_confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            "enroll_signing_key",
            scope.as_str(),
            &input,
            &idempotency_key,
            vec![format!(
                "enroll external signing key '{}' generation 1",
                input.request.name
            )],
            vec!["private key material remains outside AOS Hub".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans appending a new signing-key generation under an exact head version.
    pub async fn plan_rotate_signing_key(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanSigningKeyMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &scope)
            .await?;
        normalize_signing_key_mutation(&mut req)?;
        let baseline = self
            .db
            .signing_key(scope.as_str(), &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signing key"))?;
        if baseline.state != "active"
            || parse_resource_version(&req.expected_resource_version, baseline.resource_version)?
                != baseline.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "signing-key resource version is stale or retired".into(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = SigningKeyMutationPlanInput {
            request: req,
            baseline: Some(baseline),
        };
        let confirmation_hash = control_confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            "rotate_signing_key",
            scope.as_str(),
            &input,
            &idempotency_key,
            vec![format!(
                "append a new generation for signing key '{}' and retire its predecessor",
                input.request.name
            )],
            vec!["existing usages remain pinned to their reviewed generation".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans retirement of a signing-key head without deleting verification material.
    pub async fn plan_retire_signing_key(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanRetireSigningKeyRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &scope)
            .await?;
        req.name = req.name.trim().to_string();
        let baseline = self
            .db
            .signing_key(scope.as_str(), &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signing key"))?;
        if baseline.state != "active"
            || parse_resource_version(&req.expected_resource_version, baseline.resource_version)?
                != baseline.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "signing-key resource version is stale or retired".into(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = SigningKeyRetirementPlanInput {
            request: req,
            baseline,
        };
        let confirmation_hash = control_confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            "retire_signing_key",
            scope.as_str(),
            &input,
            &idempotency_key,
            vec![format!(
                "retire signing key '{}' for new signing work",
                input.request.name
            )],
            vec!["verification material and historical usage pins are retained".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans replacement of one typed consumer pin to an exact key generation.
    pub async fn plan_set_signing_key_usage(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanSigningKeyUsageRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        validate_signing_usage_request(&req)?;
        let consumer = self
            .db
            .resolve_signing_key_consumer(&req.consumer_stable_id, &req.purpose)
            .await
            .map_err(|error| RpcError::invalid(format!("invalid signing consumer: {error:#}")))?;
        let generation = i64::try_from(req.signing_key_generation)
            .map_err(|_| RpcError::invalid("signing_key_generation is too large"))?;
        let key = self
            .db
            .signing_key_generation(&req.signing_key_stable_id, generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signing key"))?;
        validate_signing_key_consumer_compatibility(&key, &consumer)?;
        let key_scope = parse_authorization_scope(&key.scope_key)?;
        let consumer_scope = parse_authorization_scope(&consumer.scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &key_scope)
            .await?;
        self.require_permission(&claims, Permission::KeysManage, &consumer_scope)
            .await?;
        let head = self
            .db
            .signing_key_by_stable_id(&req.signing_key_stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signing key"))?;
        if req.state == "active" && (key.state != "active" || key != head) {
            return Err(RpcError::FailedPrecondition(
                "usage must pin the current active signing-key generation".into(),
            ));
        }
        let baseline = self
            .db
            .signing_key_usage(&req.consumer_stable_id, &req.purpose)
            .await
            .map_err(RpcError::internal)?;
        let baseline_version = baseline.as_ref().map_or_else(
            || "absent".to_string(),
            |usage| usage.resource_version.to_string(),
        );
        if req.expected_resource_version != baseline_version {
            return Err(RpcError::FailedPrecondition(
                "signing-key usage resource version is stale".into(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = SigningKeyUsagePlanInput {
            request: req,
            baseline,
            consumer,
            key,
        };
        let confirmation_hash = control_confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            "set_signing_key_usage",
            consumer_scope.as_str(),
            &input,
            &idempotency_key,
            vec![format!(
                "set {} signing usage for {} to {} generation {}",
                input.request.purpose,
                input.request.consumer_stable_id,
                input.request.signing_key_stable_id,
                input.request.signing_key_generation
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }
}
