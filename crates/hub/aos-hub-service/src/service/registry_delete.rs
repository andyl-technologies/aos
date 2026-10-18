//! Reviewed registry deletion as one self-driving operation.
//!
//! The plan binds the registry identity and resource version and carries the
//! exact [`RegistryDeletionReadiness`](aos_hub_db::db::RegistryDeletionReadiness)
//! breakdown, so the review already states what blocks deletion or what the
//! operation will do first. Apply refuses a blocked registry with the same
//! breakdown and otherwise starts one `delete_registry` operation, which
//! [`RegistryDeletionController`](crate::registry_delete_controller::RegistryDeletionController)
//! drives to completion on either runtime.

use sha2::Digest;

use super::{clock, parse_resource_version, pb, Permission, RpcError, RpcService, Scope, Sha256};
use crate::registry_delete_controller::{
    readiness_message, registry_deletion_operation_id, RegistryDeletionDetail,
};
use aos_hub_db::db::{
    NewTopologyOperation, NewTopologyOperationTarget, NewTopologyOperationTargetRef,
    RegistryDeletionReadiness, RegistryDeletionVerdict, REGISTRY_DELETION_OPERATION_KIND,
};

#[cfg(test)]
#[path = "registry_delete_tests.rs"]
mod tests;

const PLAN_KIND: &str = "delete_registry";
/// Progress units of a deletion operation: prepare, scan, inventory, delete.
const OPERATION_PROGRESS_TOTAL: i64 = 4;

/// Immutable registry identity reviewed for deletion.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RegistryDeletePlanInput {
    stable_id: String,
    slug: String,
    registry_id: i64,
    owner_scope_key: String,
    expected_resource_version: i64,
}

impl RpcService {
    /// Plans deletion of one registry and reports its exact readiness.
    ///
    /// The readiness is informational: the confirmation hash binds only the
    /// registry identity and version, and apply recomputes readiness.
    pub async fn plan_delete_registry(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::RegistryDeletePlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.stable_id).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        let expected = req
            .expected_resource_version
            .as_deref()
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))
            .and_then(|value| parse_resource_version(value, 0))?;
        if expected != registry.resource_version {
            return Err(RpcError::FailedPrecondition(
                "registry resource version is stale".to_string(),
            ));
        }

        let readiness = self.registry_deletion_readiness(registry.id).await?;
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = RegistryDeletePlanInput {
            stable_id: registry.stable_id.clone(),
            slug: registry.slug.clone(),
            registry_id: registry.id,
            owner_scope_key: registry.owner_scope_key.clone(),
            expected_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        let (effects, warnings) = deletion_review_text(&registry.slug, &readiness);
        let planned = self
            .create_control_plan(
                &claims,
                PLAN_KIND,
                &registry.scope_key,
                &input,
                &idempotency_key,
                effects,
                warnings,
                Some(confirmation_hash),
            )
            .await?;
        Ok(pb::RegistryDeletePlanResponse {
            plan: planned.plan,
            readiness: Some(readiness_message(&readiness)),
        })
    }

    /// Applies a reviewed registry deletion by starting its operation.
    ///
    /// A registry with operator-resolvable blockers is refused with
    /// `failed_precondition` and the exact breakdown; nothing is changed and
    /// the plan stays unconsumed. Otherwise the returned operation acquires
    /// the purge fence, collects inventories, and deletes the registry.
    pub async fn apply_delete_registry(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
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
        let (plan, input): (_, RegistryDeletePlanInput) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&input.stable_id),
        )
        .await?;

        let operation_id = registry_deletion_operation_id(&plan.plan_id);
        let existing = self
            .db
            .topology_operation(&operation_id)
            .await
            .map_err(RpcError::internal)?;
        let operation = match existing {
            Some(operation) => operation,
            None => {
                self.start_registry_deletion(auth, &req, &plan.plan_id, &input, operation_id)
                    .await?
            }
        };
        if matches!(operation.state.as_str(), "pending" | "running") {
            self.topology_probes
                .wake_controller()
                .await
                .map_err(RpcError::internal)?;
        }

        let response = pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Validates the reviewed registry and creates its deletion operation.
    async fn start_registry_deletion(
        &self,
        auth: Option<&str>,
        req: &pb::ApplyDeleteTopologyResourceRequest,
        plan_id: &str,
        input: &RegistryDeletePlanInput,
        operation_id: String,
    ) -> Result<aos_hub_db::db::TopologyOperationRecord, RpcError> {
        let registry = self
            .db
            .registry_by_id(input.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        if registry.stable_id != input.stable_id
            || registry.owner_scope_key != input.owner_scope_key
        {
            return Err(RpcError::FailedPrecondition(
                "registry identity changed after planning".to_string(),
            ));
        }
        if registry.resource_version != input.expected_resource_version {
            return Err(RpcError::FailedPrecondition(
                "registry changed after planning".to_string(),
            ));
        }

        // Refuse before reserving the plan, so an operator can resolve the
        // reported blockers and apply the same review again.
        let readiness = self.registry_deletion_readiness(registry.id).await?;
        if readiness.verdict() == RegistryDeletionVerdict::Blocked {
            return Err(RpcError::FailedPrecondition(readiness.failure_message()));
        }

        self.begin_control_plan_apply(
            auth,
            plan_id,
            PLAN_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let detail = RegistryDeletionDetail::new(
            &registry.slug,
            plan_id,
            input.expected_resource_version,
            &readiness,
        );
        self.db
            .create_topology_operation(&NewTopologyOperation {
                operation_id,
                operation_kind: REGISTRY_DELETION_OPERATION_KIND.to_string(),
                control_permission: Permission::RegistryConfigure,
                targets: vec![NewTopologyOperationTarget {
                    role: "primary".to_string(),
                    target: NewTopologyOperationTargetRef::Registry(registry.id),
                    generation_key: 0,
                    configuration_digest: String::new(),
                }],
                detail_json: serde_json::to_string(&detail).map_err(RpcError::internal)?,
                progress_total: Some(OPERATION_PROGRESS_TOTAL),
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))
    }

    async fn registry_deletion_readiness(
        &self,
        registry_id: i64,
    ) -> Result<RegistryDeletionReadiness, RpcError> {
        self.db
            .registry_deletion_readiness(registry_id, clock::now_unix_secs())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))
    }
}

/// Builds the plan's effect and warning lines from the readiness.
fn deletion_review_text(
    slug: &str,
    readiness: &RegistryDeletionReadiness,
) -> (Vec<String>, Vec<String>) {
    let mut effects = vec![format!("start a registry deletion operation for '{slug}'")];
    effects.extend(readiness.automatic_steps());

    let mut warnings = readiness
        .blocking_reasons()
        .into_iter()
        .map(|reason| format!("blocked: {reason}"))
        .collect::<Vec<_>>();
    warnings.push(
        "physical placement objects are never deleted here; every placement must be proven \
         empty by a fresh provider inventory"
            .to_string(),
    );
    warnings.push(
        "the purge fence blocks new registry writes until deletion completes or fails".to_string(),
    );
    (effects, warnings)
}
