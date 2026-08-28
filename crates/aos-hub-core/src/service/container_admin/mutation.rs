//! Reviewed OCI repository, tag, and retention mutations.

use aos_proto_types as pb;

use super::*;
use crate::clock;
use crate::db::{
    AppliedOciAdminMutation, ApplyOciAdminMutation, OciAdminMutationRecord,
    OciManualTagMutationOperation, OciRepositoryMutationOperation, PlanOciManualTagMutation,
    PlanOciRepositoryMutation, PlanOciRetentionPolicy,
};

impl RpcService {
    /// Plans creation of an empty container repository.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, conflict, or database error.
    pub async fn plan_create_container_repository(
        &self,
        auth: Option<&str>,
        req: pb::PlanCreateContainerRepositoryRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        if !req.expected_resource_version.is_empty() {
            return Err(RpcError::invalid(
                "expectedResourceVersion must be empty when creating a repository",
            ));
        }
        let repository = repository_name(&req.repository)?;
        let plan = self
            .db
            .plan_oci_repository_mutation(&PlanOciRepositoryMutation {
                registry_id: registry.id,
                repository,
                operation: OciRepositoryMutationOperation::Create,
                description: Some(req.description),
                expected_resource_version: None,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(plan_response(
            &plan,
            vec!["create an empty OCI repository".to_string()],
            Vec::new(),
        ))
    }

    /// Plans an exact repository-description update.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or database error.
    pub async fn plan_update_container_repository(
        &self,
        auth: Option<&str>,
        req: pb::PlanUpdateContainerRepositoryRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        if req.update_mask != ["description"] {
            return Err(RpcError::invalid(
                "updateMask must contain exactly 'description'",
            ));
        }
        let repository = repository_name(&req.repository)?;
        let plan = self
            .db
            .plan_oci_repository_mutation(&PlanOciRepositoryMutation {
                registry_id: registry.id,
                repository,
                operation: OciRepositoryMutationOperation::Update,
                description: Some(req.description),
                expected_resource_version: resource_version(&req.expected_resource_version, true)?,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(plan_response(
            &plan,
            vec!["update OCI repository description".to_string()],
            Vec::new(),
        ))
    }

    /// Plans deletion of an empty repository.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or database error.
    pub async fn plan_delete_container_repository(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteContainerRepositoryRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        let repository = repository_name(&req.repository)?;
        let plan = self
            .db
            .plan_oci_repository_mutation(&PlanOciRepositoryMutation {
                registry_id: registry.id,
                repository,
                operation: OciRepositoryMutationOperation::Delete,
                description: None,
                expected_resource_version: resource_version(&req.expected_resource_version, true)?,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(plan_response(
            &plan,
            vec!["delete the empty OCI repository".to_string()],
            vec![
                "apply fails if catalog content, tags, uploads, or publications become live"
                    .to_string(),
            ],
        ))
    }

    /// Applies a reviewed repository-create plan.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, expiry, conflict, or database error.
    pub async fn create_container_repository(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerMutationRequest,
    ) -> Result<pb::ContainerRepositoryResponse, RpcError> {
        let result = self
            .apply_container_admin_plan(
                auth,
                req,
                "repository.create",
                Permission::RegistryConfigure,
            )
            .await?;
        let registry = self.registry_for_applied_plan(&result).await?;
        let repository = result.repository.as_ref().ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("repository create returned no repository"))
        })?;
        let distribution_authority = self.container_distribution_authority(registry.id).await?;
        Ok(pb::ContainerRepositoryResponse {
            repository: Some(repository_message(
                &registry.slug,
                repository,
                distribution_authority.as_deref(),
            )),
        })
    }

    /// Applies a reviewed repository-update plan.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, expiry, conflict, or database error.
    pub async fn update_container_repository(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerMutationRequest,
    ) -> Result<pb::ContainerRepositoryResponse, RpcError> {
        let result = self
            .apply_container_admin_plan(
                auth,
                req,
                "repository.update",
                Permission::RegistryConfigure,
            )
            .await?;
        let registry = self.registry_for_applied_plan(&result).await?;
        let repository = result.repository.as_ref().ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("repository update returned no repository"))
        })?;
        let distribution_authority = self.container_distribution_authority(registry.id).await?;
        Ok(pb::ContainerRepositoryResponse {
            repository: Some(repository_message(
                &registry.slug,
                repository,
                distribution_authority.as_deref(),
            )),
        })
    }

    /// Applies a reviewed empty-repository deletion.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, non-empty, expiry, or database error.
    pub async fn delete_container_repository(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerMutationRequest,
    ) -> Result<pb::ContainerDeletionResponse, RpcError> {
        let result = self
            .apply_container_admin_plan(
                auth,
                req,
                "repository.delete",
                Permission::RegistryConfigure,
            )
            .await?;
        let registry = self.registry_for_applied_plan(&result).await?;
        let deletion = result.deletion.as_ref().ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("repository delete returned no identity"))
        })?;
        Ok(pb::ContainerDeletionResponse {
            deleted: true,
            registry: registry.slug,
            repository: deletion.repository.to_string(),
            tag: String::new(),
            resource_version: deletion.resource_version.to_string(),
        })
    }

    /// Plans creation or movement of one manual tag.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, signed-tag, stale-version, or database error.
    pub async fn plan_set_container_tag(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetContainerTagRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::Publish)
            .await?;
        let expected_version = req
            .expected_resource_version
            .as_deref()
            .map(|value| resource_version(value, true))
            .transpose()?
            .flatten();
        let expected_digest = req.expected_digest.as_deref().map(digest).transpose()?;
        let plan = self
            .db
            .plan_oci_manual_tag_mutation(&PlanOciManualTagMutation {
                registry_id: registry.id,
                repository: repository_name(&req.repository)?,
                tag: tag(&req.tag)?,
                operation: OciManualTagMutationOperation::Set,
                target_digest: Some(digest(&req.target_digest)?),
                expected_digest,
                expected_resource_version: expected_version,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(plan_response(
            &plan,
            vec!["create or move one manual OCI tag".to_string()],
            vec!["signed release and channel tags remain immutable".to_string()],
        ))
    }

    /// Plans removal of one manual tag.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, signed-tag, stale-version, or database error.
    pub async fn plan_unset_container_tag(
        &self,
        auth: Option<&str>,
        req: pb::PlanUnsetContainerTagRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::Publish)
            .await?;
        let plan = self
            .db
            .plan_oci_manual_tag_mutation(&PlanOciManualTagMutation {
                registry_id: registry.id,
                repository: repository_name(&req.repository)?,
                tag: tag(&req.tag)?,
                operation: OciManualTagMutationOperation::Unset,
                target_digest: None,
                expected_digest: Some(digest(&req.expected_digest)?),
                expected_resource_version: resource_version(&req.expected_resource_version, true)?,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(plan_response(
            &plan,
            vec!["remove one manual OCI tag".to_string()],
            vec!["immutable content remains until reviewed garbage collection".to_string()],
        ))
    }

    /// Applies a reviewed manual-tag set.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, expiry, conflict, or database error.
    pub async fn set_container_tag(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerMutationRequest,
    ) -> Result<pb::ContainerTagResponse, RpcError> {
        let result = self
            .apply_container_admin_plan(auth, req, "tag.set", Permission::Publish)
            .await?;
        let registry = self.registry_for_applied_plan(&result).await?;
        let repository = result
            .mutation
            .repository_name
            .as_ref()
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("tag set has no repository")))?;
        let tag = result
            .tag
            .as_ref()
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("tag set returned no tag")))?;
        Ok(pb::ContainerTagResponse {
            tag: Some(tag_message(&registry.slug, repository, tag)),
        })
    }

    /// Applies a reviewed manual-tag removal.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, expiry, conflict, or database error.
    pub async fn unset_container_tag(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerMutationRequest,
    ) -> Result<pb::ContainerDeletionResponse, RpcError> {
        let result = self
            .apply_container_admin_plan(auth, req, "tag.unset", Permission::Publish)
            .await?;
        let registry = self.registry_for_applied_plan(&result).await?;
        let deletion = result
            .deletion
            .as_ref()
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("tag unset returned no identity")))?;
        Ok(pb::ContainerDeletionResponse {
            deleted: true,
            registry: registry.slug,
            repository: deletion.repository.to_string(),
            tag: deletion
                .tag
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            resource_version: deletion.resource_version.to_string(),
        })
    }

    /// Plans a registry-scoped retention-policy update.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or database error.
    pub async fn plan_set_container_retention_policy(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetContainerRetentionPolicyRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        let policy = req
            .policy
            .ok_or_else(|| RpcError::invalid("policy is required"))?;
        if !policy.registry.is_empty() && policy.registry != registry.slug {
            return Err(RpcError::invalid("policy registry does not match request"));
        }
        let plan = self
            .db
            .plan_oci_retention_policy(&PlanOciRetentionPolicy {
                registry_id: registry.id,
                untagged_grace_seconds: policy.untagged_grace_period_secs,
                deleted_tag_history_seconds: policy.deleted_tag_history_period_secs,
                recent_manual_tag_revisions: policy.recent_manual_tag_revisions,
                retain_referrers: policy.retain_referrers,
                expected_resource_version: resource_version(&req.expected_resource_version, false)?,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(plan_response(
            &plan,
            vec!["replace the registry OCI retention policy".to_string()],
            vec![
                "policy changes do not delete bytes until a separately reviewed GC run".to_string(),
            ],
        ))
    }

    /// Applies a reviewed registry retention-policy update.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, expiry, conflict, or database error.
    pub async fn set_container_retention_policy(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerMutationRequest,
    ) -> Result<pb::ContainerRetentionPolicyResponse, RpcError> {
        let result = self
            .apply_container_admin_plan(auth, req, "retention.set", Permission::RegistryConfigure)
            .await?;
        let registry = self.registry_for_applied_plan(&result).await?;
        let policy = result.retention_policy.as_ref().ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("retention apply returned no policy"))
        })?;
        Ok(pb::ContainerRetentionPolicyResponse {
            policy: Some(retention_message(&registry.slug, policy)),
        })
    }

    /// Refuses to create a GC plan until the Phase 7 engine is enabled.
    ///
    /// # Errors
    ///
    /// Returns authorization errors first, then unavailable until Phase 7.
    pub async fn plan_run_container_gc(
        &self,
        auth: Option<&str>,
        req: pb::PlanRunContainerGcRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let _ = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        Err(container_gc_unavailable())
    }

    /// Refuses GC apply until the Phase 7 engine is enabled.
    ///
    /// # Errors
    ///
    /// Returns authentication errors first, then unavailable until Phase 7.
    pub async fn run_container_gc(
        &self,
        auth: Option<&str>,
        _req: pb::ApplyContainerMutationRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let _ = self.require_claims(auth)?;
        Err(container_gc_unavailable())
    }

    async fn apply_container_admin_plan(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerMutationRequest,
        expected_kind: &str,
        permission: Permission,
    ) -> Result<AppliedOciAdminMutation, RpcError> {
        let claims = self.require_claims(auth)?;
        let plan = self
            .db
            .oci_admin_mutation_for_actor(&req.plan_id, &claims.sub)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container mutation plan"))?;
        if plan.mutation_kind != expected_kind {
            return Err(RpcError::FailedPrecondition(
                "container mutation plan does not match this method".to_string(),
            ));
        }
        let registry = self
            .db
            .registry_by_id(plan.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        if let Some(org_id) = registry.org_id {
            if !self
                .db
                .org_is_active(org_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::not_found("container mutation plan"));
            }
        }
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, permission, &scope).await?;
        self.db
            .apply_oci_admin_mutation(&ApplyOciAdminMutation {
                mutation_id: req.plan_id,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                confirmation_hash: digest(&req.confirmation_hash)?,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)
    }

    async fn registry_for_applied_plan(
        &self,
        result: &AppliedOciAdminMutation,
    ) -> Result<RegistryRecord, RpcError> {
        self.db
            .registry_by_id(result.mutation.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))
    }
}

fn plan_response(
    plan: &OciAdminMutationRecord,
    effects: Vec<String>,
    warnings: Vec<String>,
) -> pb::TopologyPlanResponse {
    pb::TopologyPlanResponse {
        plan: Some(pb::TopologyPlan {
            plan_id: plan.id.clone(),
            expires_at: plan.expires_at,
            input_versions: plan
                .expected_resource_version
                .map(|version| vec![format!("resource_version={version}")])
                .unwrap_or_default(),
            effects,
            warnings,
            confirmation_hash: plan.confirmation_hash.to_string(),
            pin_impacts: Vec::new(),
        }),
    }
}

fn plan_error(error: anyhow::Error) -> RpcError {
    RpcError::FailedPrecondition(format!("{error:#}"))
}
