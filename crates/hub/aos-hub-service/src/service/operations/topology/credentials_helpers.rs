//! Credentials helpers in the topology capability.

use super::*;

impl RpcService {
    /// Projects a credential revision without resolving or exposing secret material.
    pub(in crate::service) fn binding_credential_message(
        stable_id: &str,
        record: crate::db::BindingCredentialRevisionRecord,
    ) -> pb::BindingCredential {
        pb::BindingCredential {
            binding_id: stable_id.to_string(),
            purpose: record.purpose,
            generation: record.generation,
            secret_version_ref: record.secret_version_ref,
            validation_state: record.validation_state,
            validated_at: record.validated_at.unwrap_or_default(),
            validation_error: record.validation_error.unwrap_or_default(),
            credential_fingerprint: record.credential_fingerprint,
            created_at: record.created_at,
            resource_version: record.head_resource_version.to_string(),
        }
    }

    /// Persists a credential set/rotation plan after resolving exact head state.
    pub(in crate::service) async fn plan_binding_credential(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanBindingCredentialRequest,
        rotate: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.secret_version_ref.trim().is_empty() {
            return Err(RpcError::invalid("secretVersionRef is required"));
        }
        if !matches!(
            req.purpose.as_str(),
            "read" | "write" | "delete" | "list" | "presign"
        ) {
            return Err(RpcError::invalid("credential purpose is invalid"));
        }
        let binding = self
            .db
            .binding_by_stable_id(&req.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        let owner_scope_key = binding.owner_scope_key.clone();
        self.writable_storage_owner(auth, &owner_scope_key).await?;
        if !matches!(binding.kind.as_str(), "s3" | "r2")
            || binding.access_mode.as_deref() != Some("private")
        {
            return Err(RpcError::invalid(
                "credential revisions are supported only by private external s3/r2 bindings",
            ));
        }
        let expected_binding_version =
            parse_resource_version(&req.expected_resource_version, binding.resource_version)?;
        if expected_binding_version != binding.resource_version {
            return Err(RpcError::FailedPrecondition(
                "binding changed before credential planning".to_string(),
            ));
        }
        let current = self
            .db
            .current_binding_credential(binding.id, &req.purpose)
            .await
            .map_err(RpcError::internal)?;
        let current_generation = current.as_ref().map_or(0, |record| record.generation);
        if current_generation != req.expected_current_generation
            || rotate != (current_generation > 0)
        {
            return Err(RpcError::FailedPrecondition(
                "credential generation does not match set/rotate semantics".to_string(),
            ));
        }
        req.secret_version_ref = req.secret_version_ref.trim().to_string();
        crate::secret_version::validate_secret_version_ref(&req.secret_version_ref)
            .map_err(|error| RpcError::invalid(format!("invalid secretVersionRef: {error:#}")))?;
        req.credential_fingerprint = req.credential_fingerprint.trim().to_ascii_lowercase();
        if req.credential_fingerprint.len() != 64
            || !req
                .credential_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RpcError::invalid(
                "credentialFingerprint is required and must be SHA-256 hex",
            ));
        }
        let secrets = self.secret_versions.as_deref().ok_or_else(|| {
            RpcError::FailedPrecondition("secret-version provider is not configured".to_string())
        })?;
        let resolved = secrets
            .resolve(&req.secret_version_ref)
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!(
                    "secret version cannot be resolved: {error:#}"
                ))
            })?;
        crate::secret_version::verify_secret_fingerprint(&resolved, &req.credential_fingerprint)
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        drop(resolved);
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let credential_fingerprint = req.credential_fingerprint.clone();
        let input = BindingCredentialPlanInput {
            request: req,
            binding_db_id: binding.id,
            owner_scope_key: owner_scope_key.clone(),
            credential_fingerprint,
        };
        let plan_kind = if rotate {
            "rotate_binding_credential"
        } else {
            "set_binding_credential"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "{} '{}' credential generation {}",
                if rotate { "rotate" } else { "set" },
                input.request.purpose,
                current_generation + 1
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Applies a credential set/rotation plan with exact-result recovery.
    pub(in crate::service) async fn apply_binding_credential(
        &self,
        auth: Option<&str>,
        req: pb::ApplyBindingCredentialRequest,
        rotate: bool,
    ) -> Result<pb::BindingCredentialResponse, RpcError> {
        let plan_kind = if rotate {
            "rotate_binding_credential"
        } else {
            "set_binding_credential"
        };
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                plan_kind,
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
            plan_kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, BindingCredentialPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        self.writable_storage_owner(auth, &input.owner_scope_key)
            .await?;
        let binding = self
            .db
            .binding_by_stable_id(&input.request.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        if binding.id != input.binding_db_id {
            return Err(RpcError::FailedPrecondition(
                "binding identity changed after credential planning".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let record = self
            .db
            .set_binding_credential_revision(
                binding.id,
                &input.request.purpose,
                &input.request.secret_version_ref,
                input.request.expected_current_generation,
                &input.credential_fingerprint,
                &claims.sub,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::BindingCredentialResponse {
            credential: Some(Self::binding_credential_message(
                &input.request.binding_id,
                record,
            )),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Queues controller validation of the current credential generation.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or scheduling error.
    pub(in crate::service) async fn execute_validate_binding_credential(
        &self,
        auth: Option<&str>,
        req: pb::PlanValidateBindingCredentialRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let binding = self
            .db
            .binding_by_stable_id(&req.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        self.writable_storage_owner(auth, &binding.owner_scope_key)
            .await?;
        let current = if req.generation == 0 {
            self.db
                .current_binding_credential(binding.id, &req.purpose)
                .await
                .map_err(RpcError::internal)?
        } else {
            self.db
                .binding_credential_revision(binding.id, &req.purpose, req.generation)
                .await
                .map_err(RpcError::internal)?
        }
        .ok_or_else(|| RpcError::not_found("binding credential"))?;
        let expected = parse_resource_version(
            &req.expected_resource_version,
            current.head_resource_version,
        )?;
        if !matches!(
            req.purpose.as_str(),
            "read" | "write" | "delete" | "list" | "presign"
        ) {
            return Err(RpcError::invalid(
                "purpose must be read, write, delete, list, or presign",
            ));
        }
        let operation_id = hex::encode(Sha256::digest(
            format!(
                "storage-credential-probe-v1\0{}\0{}\0{}\0{}\0{}",
                binding.stable_id, req.purpose, current.generation, expected, req.idempotency_key
            )
            .as_bytes(),
        ));
        let operation = self
            .topology_probes
            .schedule(
                &operation_id,
                crate::topology_probe::TopologyProbe::StorageCredential {
                    stable_id: binding.stable_id,
                    binding_id: binding.id,
                    binding_resource_version: binding.resource_version,
                    purpose: req.purpose,
                    generation: current.generation,
                    credential_head_resource_version: expected,
                },
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!(
                    "schedule storage credential probe: {error:#}"
                ))
            })?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        })
    }
}
