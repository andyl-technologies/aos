//! Reviewed OCI repository, tag, and retention mutations.

use aos_proto_types as pb;

use super::*;
use crate::clock;
use crate::db::{
    AppliedOciAdminMutation, ApplyOciAdminMutation, ApplyOciGc, ApplyOciRegistryPurgeFence,
    ApplyOciUntrackedRepair, OciAdminMutationRecord, OciManualTagMutationOperation,
    OciRegistryPurgeFenceAction, OciRepositoryMutationOperation, OciUntrackedRepairKind, PlanOciGc,
    PlanOciManualTagMutation, PlanOciRegistryPurgeFence, PlanOciRepositoryMutation,
    PlanOciRetentionPolicy, PlanOciUntrackedRepair, RequeueOciGcPlacementAction,
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
        if !self.container_rollout.administration {
            return Err(container_administration_unavailable());
        }
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
        if !self.container_rollout.administration {
            return Err(container_administration_unavailable());
        }
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
        if !self.container_rollout.administration {
            return Err(container_administration_unavailable());
        }
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
        if !self.container_rollout.administration {
            return Err(container_administration_unavailable());
        }
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
        if !self.container_rollout.administration {
            return Err(container_administration_unavailable());
        }
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
        if !self.container_rollout.administration {
            return Err(container_administration_unavailable());
        }
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

    /// Creates one durable, actor-bound GC review plan.
    ///
    /// # Errors
    ///
    /// Returns authorization, validation, stale-policy, or database errors.
    pub async fn plan_run_container_gc(
        &self,
        auth: Option<&str>,
        req: pb::PlanRunContainerGcRequest,
    ) -> Result<pb::ContainerGcPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        if !self.container_rollout.garbage_collection {
            return Err(container_gc_rollout_unavailable());
        }
        let expected_resource_version =
            req.expected_resource_version.parse::<i64>().map_err(|_| {
                RpcError::invalid("expectedResourceVersion must be a non-negative integer")
            })?;
        if expected_resource_version < 0 {
            return Err(RpcError::invalid(
                "expectedResourceVersion must be a non-negative integer",
            ));
        }
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }

        let run = self
            .db
            .plan_oci_gc(&PlanOciGc {
                registry_id: registry.id,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                expected_resource_version,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        let blockers = self
            .db
            .list_oci_gc_blockers(&run.id)
            .await
            .map_err(RpcError::internal)?;

        Ok(pb::ContainerGcPlanResponse {
            plan: Some(gc_topology_plan(&run, &blockers)),
            run: Some(gc_run_message(&registry.slug, &run, &blockers)),
            blockers: blockers.iter().map(gc_blocker_message).collect(),
        })
    }

    /// Applies one actor-bound reviewed GC plan after exact revalidation.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, confirmation, expiry, or database errors.
    pub async fn run_container_gc(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerMutationRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let plan = self
            .db
            .oci_gc_generation_for_actor(&req.plan_id, &claims.sub)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container GC plan"))?;
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
                return Err(RpcError::not_found("container GC plan"));
            }
        }
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::RegistryConfigure, &scope)
            .await?;
        if !self.container_rollout.garbage_collection {
            return Err(container_gc_rollout_unavailable());
        }
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let result = self
            .db
            .apply_oci_gc(&ApplyOciGc {
                generation_id: req.plan_id,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                confirmation_hash: digest(&req.confirmation_hash)?,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: result.id,
                kind: "container_gc".to_string(),
                state: result.state,
                created_at: result.created_at,
            }),
        })
    }

    /// Requeues one failed action without changing its frozen deletion identity.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, validation, stale-version,
    /// idempotency, state, or database errors.
    pub async fn requeue_container_gc_placement_action(
        &self,
        auth: Option<&str>,
        req: pb::RequeueContainerGcPlacementActionRequest,
    ) -> Result<pb::ContainerGcPlacementActionResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        if !self.container_rollout.garbage_collection {
            return Err(container_gc_rollout_unavailable());
        }
        let expected_resource_version = resource_version(&req.expected_resource_version, true)?
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let run = self
            .db
            .oci_gc_generation(registry.id, &req.run_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container GC run"))?;
        let action = self
            .db
            .oci_gc_placement_action(&req.action_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|action| action.generation_id == run.id)
            .ok_or_else(|| RpcError::not_found("container GC placement action"))?;
        let action = self
            .db
            .requeue_oci_gc_placement_action(&RequeueOciGcPlacementAction {
                action_id: action.id,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                expected_resource_version,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(pb::ContainerGcPlacementActionResponse {
            action: Some(gc_placement_action_message(&action)),
            mutation_epoch: run.captured_mutation_epoch.to_string(),
        })
    }

    /// Plans exact conditional deletion of one current-head untracked object.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, rollout, validation, stale
    /// inventory/topology/capability, or database errors.
    pub async fn plan_repair_container_untracked_object(
        &self,
        auth: Option<&str>,
        req: pb::PlanRepairContainerUntrackedObjectRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        if !self.container_rollout.garbage_collection {
            return Err(container_gc_rollout_unavailable());
        }
        if req.placement_id <= 0 {
            return Err(RpcError::invalid("placementId must be positive"));
        }
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let plan = self
            .db
            .plan_oci_untracked_repair(&PlanOciUntrackedRepair {
                registry_id: registry.id,
                placement_id: req.placement_id,
                inventory_generation_id: req.inventory_generation_id,
                object_key: req.object_key,
                repair_kind: OciUntrackedRepairKind::Delete,
                adopt_media_type: None,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                expected_mutation_epoch: mutation_epoch(&req.expected_resource_version)?,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;

        Ok(pb::TopologyPlanResponse {
            plan: Some(pb::TopologyPlan {
                plan_id: plan.id.clone(),
                expires_at: plan.expires_at,
                input_versions: vec![
                    format!("resource_version={}", plan.resource_version),
                    format!("mutation_epoch={}", plan.captured_mutation_epoch),
                    format!("inventory_generation_id={}", plan.inventory_generation_id),
                    format!("inventory_digest={}", plan.inventory_digest),
                    format!(
                        "placement_resource_version={}",
                        plan.placement_resource_version
                    ),
                    format!("binding_write_revision={}", plan.binding_write_revision),
                    format!(
                        "delete_capability_resource_version={}",
                        plan.delete_capability_resource_version
                    ),
                ],
                effects: vec![format!(
                    "conditionally delete untracked provider object {} from placement {}",
                    plan.object_key, plan.placement_name
                )],
                warnings: vec![
                    format!(
                        "exact observed identity: digest={}, hash={}, size={}, strong_etag={}",
                        plan.object_digest, plan.observed_hash, plan.byte_size, plan.strong_etag
                    ),
                    "registry purge still requires a fresh complete post-repair inventory"
                        .to_string(),
                ],
                confirmation_hash: plan.confirmation_hash.to_string(),
                pin_impacts: Vec::new(),
            }),
        })
    }

    /// Applies one actor-bound reviewed untracked-object conditional repair.
    ///
    /// # Errors
    ///
    /// Returns authentication, masked ownership, authorization, rollout,
    /// confirmation, CAS, expiry, idempotency, or database errors.
    pub async fn repair_container_untracked_object(
        &self,
        auth: Option<&str>,
        req: pb::RepairContainerUntrackedObjectRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let plan = self
            .db
            .oci_untracked_repair_plan_for_actor(&req.plan_id, &claims.sub)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container untracked repair plan"))?;
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
                return Err(RpcError::not_found("container untracked repair plan"));
            }
        }
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::RegistryConfigure, &scope)
            .await?;
        if !self.container_rollout.garbage_collection {
            return Err(container_gc_rollout_unavailable());
        }
        require_public_untracked_repair_kind(plan.repair_kind)?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let expected_resource_version = resource_version(&req.expected_resource_version, true)?
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?;
        let result = self
            .db
            .apply_oci_untracked_repair(&ApplyOciUntrackedRepair {
                plan_id: req.plan_id,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                confirmation_hash: digest(&req.confirmation_hash)?,
                expected_resource_version,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: result.id,
                kind: "container_untracked_repair".to_string(),
                state: public_untracked_repair_state(&result.state).to_string(),
                created_at: result.created_at,
            }),
        })
    }

    /// Plans acquisition or explicit abort of a registry purge writer fence.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, rollout, action, version,
    /// idempotency, stale-state, or database errors.
    pub async fn plan_container_registry_purge_fence(
        &self,
        auth: Option<&str>,
        req: pb::PlanContainerRegistryPurgeFenceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (claims, registry) = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        if !self.container_rollout.garbage_collection {
            return Err(container_gc_rollout_unavailable());
        }
        let action = match pb::ContainerRegistryPurgeFenceAction::try_from(req.action) {
            Ok(pb::ContainerRegistryPurgeFenceAction::Begin) => OciRegistryPurgeFenceAction::Begin,
            Ok(pb::ContainerRegistryPurgeFenceAction::Abort) => OciRegistryPurgeFenceAction::Abort,
            _ => return Err(RpcError::invalid("action must be BEGIN or ABORT")),
        };
        let expected_resource_version = resource_version(&req.expected_resource_version, true)?
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let plan = self
            .db
            .plan_oci_registry_purge_fence(&PlanOciRegistryPurgeFence {
                registry_id: registry.id,
                action,
                actor_id: claims.sub,
                idempotency_key: req.idempotency_key,
                expected_resource_version,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        let action_name = match plan.action {
            OciRegistryPurgeFenceAction::Begin => "acquire",
            OciRegistryPurgeFenceAction::Abort => "abort",
        };
        Ok(pb::TopologyPlanResponse {
            plan: Some(pb::TopologyPlan {
                plan_id: plan.id,
                expires_at: plan.expires_at,
                input_versions: vec![
                    format!("resource_version={}", plan.resource_version),
                    format!("expected_resource_version={}", plan.expected_resource_version),
                    format!("mutation_epoch={}", plan.captured_mutation_epoch),
                ],
                effects: vec![format!(
                    "{action_name} the OCI purge writer fence for registry {}",
                    registry.slug
                )],
                warnings: match plan.action {
                    OciRegistryPurgeFenceAction::Begin => vec![
                        "the fence blocks new OCI writes until final deletion or reviewed abort"
                            .to_string(),
                        "final deletion still requires a fresh complete empty inventory captured after this fence"
                            .to_string(),
                    ],
                    OciRegistryPurgeFenceAction::Abort => vec![
                        "aborting the fence reopens writes and invalidates prior purge readiness"
                            .to_string(),
                    ],
                },
                confirmation_hash: plan.confirmation_hash.to_string(),
                pin_impacts: Vec::new(),
            }),
        })
    }

    /// Applies one actor-bound reviewed registry purge-fence transition.
    ///
    /// # Errors
    ///
    /// Returns authentication, masked ownership, authorization, rollout,
    /// confirmation, CAS, expiry, idempotency, stale-state, or database errors.
    pub async fn apply_container_registry_purge_fence(
        &self,
        auth: Option<&str>,
        req: pb::ApplyContainerRegistryPurgeFenceRequest,
    ) -> Result<pb::ContainerRegistryPurgeFenceResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let plan = self
            .db
            .oci_registry_purge_fence_plan_for_actor(&req.plan_id, &claims.sub)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container registry purge-fence plan"))?;
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
                return Err(RpcError::not_found("container registry purge-fence plan"));
            }
        }
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::RegistryConfigure, &scope)
            .await?;
        if !self.container_rollout.garbage_collection {
            return Err(container_gc_rollout_unavailable());
        }
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let expected_resource_version = resource_version(&req.expected_resource_version, true)?
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?;
        self.db
            .apply_oci_registry_purge_fence(&ApplyOciRegistryPurgeFence {
                plan_id: req.plan_id.clone(),
                actor_id: claims.sub.clone(),
                idempotency_key: req.idempotency_key,
                confirmation_hash: digest(&req.confirmation_hash)?,
                expected_resource_version,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(plan_error)?;
        let status = self
            .db
            .oci_registry_purge_fence_status_for_actor(
                &req.plan_id,
                &claims.sub,
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container registry purge-fence plan"))?;
        Ok(pb::ContainerRegistryPurgeFenceResponse {
            fence: Some(registry_purge_fence_message(&registry.slug, &status)),
        })
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
        if !self.container_rollout.administration {
            return Err(container_administration_unavailable());
        }
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

/// Restricts the public repair endpoint to exact conditional deletion.
pub(super) fn require_public_untracked_repair_kind(
    repair_kind: OciUntrackedRepairKind,
) -> Result<(), RpcError> {
    if repair_kind != OciUntrackedRepairKind::Delete {
        return Err(RpcError::FailedPrecondition(
            "container untracked repair plan is not a public delete plan".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod untracked_repair_tests {
    use super::*;

    #[test]
    fn public_untracked_repair_rejects_internal_adoption_plans() {
        assert!(require_public_untracked_repair_kind(OciUntrackedRepairKind::Delete).is_ok());
        assert!(matches!(
            require_public_untracked_repair_kind(OciUntrackedRepairKind::Adopt),
            Err(RpcError::FailedPrecondition(message))
                if message == "container untracked repair plan is not a public delete plan"
        ));
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

fn gc_topology_plan(
    run: &crate::db::OciGcGenerationRecord,
    blockers: &[crate::db::OciGcBlockerRecord],
) -> pb::TopologyPlan {
    pb::TopologyPlan {
        plan_id: run.id.clone(),
        expires_at: run.expires_at,
        input_versions: vec![
            format!("policy_resource_version={}", run.policy_resource_version),
            format!("captured_mutation_epoch={}", run.captured_mutation_epoch),
            format!("policy_digest={}", run.policy_digest),
            format!("root_set_digest={}", run.root_set_digest),
            format!(
                "placement_inventory_digest={}",
                run.placement_inventory_digest
            ),
            format!("topology_digest={}", run.topology_digest),
            format!("plan_digest={}", run.plan_digest),
        ],
        effects: vec![
            format!("delete {} immutable OCI objects", run.planned_objects),
            format!("reclaim {} compressed bytes", run.planned_bytes),
            format!(
                "execute {} conditional placement deletions",
                run.placement_action_count
            ),
        ],
        warnings: blockers
            .iter()
            .map(|blocker| format!("{}: {}", blocker.kind, blocker.detail))
            .collect(),
        confirmation_hash: run.confirmation_hash.to_string(),
        pin_impacts: Vec::new(),
    }
}

fn plan_error(error: anyhow::Error) -> RpcError {
    RpcError::FailedPrecondition(format!("{error:#}"))
}
