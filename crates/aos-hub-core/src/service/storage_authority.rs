//! Operator plans for permanent physical storage authority at instance root.
//!
//! The operator persists exact reviewed decisions and reads desired SQL state.
//! Authentication and current root permission are checked again on every apply,
//! including durable result replay. Executor control and provider I/O are separate.

use super::*;
use crate::db::ReviewedStorageAuthorityDecision;
use crate::storage_authority::{
    canonical_digest, StorageAuthorityDecisionInput, StorageAuthorityReviewedPlanInput,
};

mod conversion;

impl RpcService {
    /// Plans one typed permanent authority decision under current root authority.
    ///
    /// # Errors
    /// Returns an error for missing root permission, malformed input, a conflicting
    /// request idempotency key, or database failure.
    pub async fn plan_storage_authority_decision(
        &self,
        auth: Option<&str>,
        req: pb::PlanStorageAuthorityDecisionRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.storage_authority_manager(auth).await?;
        if req.idempotency_key.is_empty() || req.idempotency_key.len() > 128 {
            return Err(RpcError::invalid(
                "plan idempotency key is required and bounded",
            ));
        }
        let input = conversion::decision(req.decision)?;
        let reviewed = StorageAuthorityReviewedPlanInput {
            schema_version: 1,
            expected_resource_version: req.expected_resource_version,
            decision: input.clone(),
        };
        reviewed.validate().map_err(|_| {
            RpcError::FailedPrecondition(
                "storage authority target version differs from typed intent".into(),
            )
        })?;
        let confirmation = canonical_digest(&reviewed).map_err(RpcError::internal)?;

        // Exact planning retries retain the original review even after its
        // mutable target advances. Changed intent still fails the request key.
        if let Some((plan, stored)) = self
            .replayed_control_plan_input::<StorageAuthorityReviewedPlanInput>(
                &claims,
                input.plan_kind(),
                &req.idempotency_key,
            )
            .await
            .map_err(|_| {
                RpcError::FailedPrecondition("stored authority review cannot be replayed".into())
            })?
        {
            if stored != reviewed || plan.confirmation_hash.as_deref() != Some(&confirmation) {
                return Err(RpcError::FailedPrecondition(
                    "decision differs from its exact reviewed root plan".into(),
                ));
            }
            return Self::control_plan_response(plan);
        }
        if reviewed.expected_resource_version
            != self.storage_authority_resource_version(&input).await?
        {
            return Err(RpcError::FailedPrecondition(
                "storage authority resource version differs from the reviewed target".into(),
            ));
        }
        self.validate_storage_authority_target(&input).await?;
        let warning = "Executor reconciliation is pending; desired SQL state does not authorize provider operations.";

        let plan = self
            .create_control_plan(
                &claims,
                input.plan_kind(),
                Scope::root().as_str(),
                &reviewed,
                &req.idempotency_key,
                vec![authority_effect(&input)],
                vec![warning.into()],
                Some(confirmation),
            )
            .await?;

        Ok(plan)
    }

    /// Applies or replays the exact reviewed decision after fresh root permission.
    ///
    /// # Errors
    /// Returns an error for revoked root authority, changed input/actor/key,
    /// confirmation mismatch, unreserved expiry, stale state, or database failure.
    pub async fn apply_storage_authority_decision(
        &self,
        auth: Option<&str>,
        req: pb::ApplyStorageAuthorityDecisionRequest,
    ) -> Result<pb::StorageAuthorityDecisionResponse, RpcError> {
        let claims = self.storage_authority_manager(auth).await?;
        if req.idempotency_key.is_empty() || req.idempotency_key.len() > 128 {
            return Err(RpcError::invalid(
                "apply idempotency key is required and bounded",
            ));
        }

        let plan = self
            .db
            .topology_plan(&req.plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("physical authority plan"))?;

        if !Self::plan_actor_matches(&plan, &claims) {
            return Err(RpcError::FailedPrecondition(
                "plan belongs to another account incarnation or requires replanning".into(),
            ));
        }

        let reviewed: StorageAuthorityReviewedPlanInput =
            serde_json::from_str(&plan.input_versions_json).map_err(|_| {
                RpcError::FailedPrecondition("stored authority review is invalid".into())
            })?;
        reviewed.validate().map_err(|_| {
            RpcError::FailedPrecondition("stored authority review is invalid".into())
        })?;
        let input = &reviewed.decision;

        if plan.scope != Scope::root().as_str()
            || plan.plan_kind != input.plan_kind()
            || plan.input_versions_json
                != serde_json::to_string(&reviewed).map_err(RpcError::internal)?
            || plan.confirmation_hash.as_deref() != Some(req.confirmation_hash.as_str())
            || canonical_digest(&reviewed).map_err(RpcError::internal)? != req.confirmation_hash
        {
            return Err(RpcError::FailedPrecondition(
                "decision differs from its exact reviewed root plan".into(),
            ));
        }

        if plan.applied_at.is_none() {
            if plan.expires_at < clock::now_unix_secs()
                && plan.apply_idempotency_key.as_deref() != Some(req.idempotency_key.as_str())
            {
                return Err(RpcError::FailedPrecondition(
                    "plan expired before apply began".into(),
                ));
            }
            if let Err(error) = self
                .db
                .begin_topology_plan_apply(&req.plan_id, &req.idempotency_key)
                .await
            {
                // Reservation may lose to the same completed retry. The atomic
                // DB helper still rechecks its exact actor, input and apply key.
                let completed = self
                    .db
                    .topology_plan(&req.plan_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("physical authority plan"))?;
                if completed.applied_at.is_none()
                    || completed.apply_idempotency_key.as_deref()
                        != Some(req.idempotency_key.as_str())
                {
                    return Err(RpcError::FailedPrecondition(format!(
                        "reserve authority decision: {error:#}"
                    )));
                }
            }
        }

        // Memberships may have changed while loading or reserving the plan.
        // Reauthorize before mutation and before returning an applied result.
        let claims = self.storage_authority_manager(auth).await?;
        let result = self
            .db
            .apply_storage_authority_decision(
                &ReviewedStorageAuthorityDecision {
                    plan_id: req.plan_id,
                    apply_idempotency_key: req.idempotency_key,
                    confirmation_hash: req.confirmation_hash,
                    actor_kind: claims.owner_kind,
                    actor_id: claims.owner_id,
                    actor_incarnation: claims.owner_incarnation,
                },
                input,
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!("apply authority decision: {error:#}"))
            })?;

        Ok(pb::StorageAuthorityDecisionResponse {
            authority_id: result.authority_id.as_str().into(),
            record_id: result.record_id,
            desired_generation: result
                .admission_generation
                .map(|generation| generation.to_string()),
            pending_reconciliation: true,
        })
    }

    /// Reads permanent identity and desired admission under current root authority.
    ///
    /// SQL acknowledgements do not certify fresh executor agreement. This
    /// projection always reports reconciliation as pending in this milestone.
    ///
    /// # Errors
    /// Returns an error for missing root permission, malformed or unknown identity,
    /// corrupt stored state, or database failure.
    pub async fn get_storage_authority(
        &self,
        auth: Option<&str>,
        req: pb::GetStorageAuthorityRequest,
    ) -> Result<pb::StorageAuthorityProjection, RpcError> {
        self.storage_authority_manager(auth).await?;
        let id = conversion::authority_id(&req.authority_id)?;
        let authority = self
            .db
            .physical_storage_authority(&id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("physical authority"))?;
        let desired = self
            .db
            .desired_storage_authority_admission(&id)
            .await
            .map_err(RpcError::internal)?
            .map(|desired| pb::StorageAuthorityDesiredAdmission {
                desired_generation: desired.generation.to_string(),
                digest: desired.digest,
                decision: Some(conversion::admission_message(desired.specification)),
            });

        let resource_version = canonical_digest(&authority).map_err(RpcError::internal)?;
        Ok(pb::StorageAuthorityProjection {
            resource_version,
            authority: Some(conversion::creation_message(authority)),
            desired_admission: desired,
            pending_reconciliation: true,
        })
    }

    // This binds the canonical request field to the actual reviewed target.
    // Immutable authority facts cannot change; mutable binding/admission fences
    // are also contained in the typed decision and checked atomically on apply.
    async fn storage_authority_resource_version(
        &self,
        input: &StorageAuthorityDecisionInput,
    ) -> Result<String, RpcError> {
        let authority_id = match input {
            StorageAuthorityDecisionInput::Create(_) => return Ok(String::new()),
            StorageAuthorityDecisionInput::AssociateBinding(spec) => {
                return Ok(spec.binding_resource_version.to_string());
            }
            StorageAuthorityDecisionInput::SetAdmission(spec) => {
                return Ok(spec.expected_generation.to_string());
            }
            StorageAuthorityDecisionInput::ApproveAlias(spec) => &spec.authority_id,
            StorageAuthorityDecisionInput::Attest(spec) => &spec.authority_id,
        };
        let authority = self
            .db
            .physical_storage_authority(authority_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("physical authority"))?;
        canonical_digest(&authority).map_err(RpcError::internal)
    }

    async fn validate_storage_authority_target(
        &self,
        input: &StorageAuthorityDecisionInput,
    ) -> Result<(), RpcError> {
        let stale = match input {
            StorageAuthorityDecisionInput::Create(spec) => self
                .db
                .physical_storage_authority(&spec.authority_id)
                .await
                .map_err(RpcError::internal)?
                .is_some(),
            StorageAuthorityDecisionInput::AssociateBinding(spec) => {
                let binding = self
                    .db
                    .binding_by_stable_id(&spec.binding_stable_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("binding"))?;
                binding.resource_version != spec.binding_resource_version
                    || binding.id != spec.binding_id
            }
            StorageAuthorityDecisionInput::SetAdmission(spec) => {
                let current = self
                    .db
                    .desired_storage_authority_admission(&spec.authority_id)
                    .await
                    .map_err(RpcError::internal)?;
                current.as_ref().map_or(0, |head| head.generation) != spec.expected_generation
                    || current.as_ref().map(|head| &head.digest) != spec.expected_digest.as_ref()
            }
            StorageAuthorityDecisionInput::ApproveAlias(_)
            | StorageAuthorityDecisionInput::Attest(_) => false,
        };
        if stale {
            return Err(RpcError::FailedPrecondition(
                "storage authority target advanced or already exists".into(),
            ));
        }
        Ok(())
    }

    async fn storage_authority_manager(&self, auth: Option<&str>) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::StorageManage, &Scope::root())
            .await?;
        Ok(claims)
    }
}

fn authority_effect(input: &StorageAuthorityDecisionInput) -> String {
    match input {
        StorageAuthorityDecisionInput::Create(spec) => format!(
            "Create permanent physical authority {} in executor namespace {} with qualified prefix {:?}",
            spec.authority_id.as_str(),
            spec.guard_namespace_id,
            spec.qualified_managed_prefix,
        ),
        StorageAuthorityDecisionInput::ApproveAlias(spec) => format!(
            "Reserve exact HTTPS bucket address for alias {} under physical authority {}",
            spec.alias_id,
            spec.authority_id.as_str(),
        ),
        StorageAuthorityDecisionInput::AssociateBinding(spec) => format!(
            "Associate binding {} at resource version {} and writer revision {} with physical authority {}",
            spec.binding_stable_id,
            spec.binding_resource_version,
            spec.binding_write_revision,
            spec.authority_id.as_str(),
        ),
        StorageAuthorityDecisionInput::Attest(spec) => format!(
            "Record exclusivity attestation {} for physical authority {} until {}",
            spec.attestation_id,
            spec.authority_id.as_str(),
            spec.valid_until,
        ),
        StorageAuthorityDecisionInput::SetAdmission(spec) => format!(
            "Append desired {:?} admission generation {} for physical authority {}",
            spec.state,
            spec.expected_generation + 1,
            spec.authority_id.as_str(),
        ),
    }
}

#[cfg(test)]
mod tests;
