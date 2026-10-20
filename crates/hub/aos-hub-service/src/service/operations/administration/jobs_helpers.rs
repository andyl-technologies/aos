//! Jobs helpers in the administration capability.

use super::*;

impl RpcService {
    /// Persists the reviewed intent for an externally-effectful operation.
    pub(in crate::service) async fn plan_external_operation<T: serde::Serialize>(
        &self,
        auth: Option<&str>,
        plan_kind: &str,
        input: &T,
        idempotency_key: &str,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            Scope::root().as_str(),
            input,
            idempotency_key,
            vec![format!("schedule the reviewed {plan_kind} operation")],
            vec!["external work begins only after apply".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn operation_detail(
        &self,
        operation: &aos_hub_db::db::TopologyOperationRecord,
    ) -> Result<pb::OperationDetail, RpcError> {
        let targets = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await
            .map_err(RpcError::internal)?;
        let targets = targets
            .into_iter()
            .map(|target| {
                let target_ref = match target.target_kind.as_str() {
                    "registry" => pb::operation_target::Target::RegistryId(target.stable_id),
                    "binary_cache" => pb::operation_target::Target::BinaryCacheId(target.stable_id),
                    "placement" => pb::operation_target::Target::PlacementId(target.stable_id),
                    "domain" => pb::operation_target::Target::DomainId(target.stable_id),
                    "network_policy" => {
                        pb::operation_target::Target::NetworkPolicyId(target.stable_id)
                    }
                    "endpoint" => pb::operation_target::Target::EndpointId(target.stable_id),
                    "gateway" => pb::operation_target::Target::GatewayId(target.stable_id),
                    "route" => pb::operation_target::Target::RouteId(target.stable_id),
                    "placement_policy" => {
                        pb::operation_target::Target::PlacementPolicyId(target.stable_id)
                    }
                    "retention_subscription" => {
                        pb::operation_target::Target::RetentionSubscriptionId(target.stable_id)
                    }
                    "population_target" => {
                        pb::operation_target::Target::PopulationTargetId(target.stable_id)
                    }
                    "cache_gc_generation" => {
                        pb::operation_target::Target::CacheGcGenerationId(target.stable_id)
                    }
                    "binding" => pb::operation_target::Target::BindingId(target.stable_id),
                    kind => {
                        return Err(RpcError::internal(anyhow::anyhow!(
                            "operation has unknown target kind '{kind}'"
                        )));
                    }
                };
                Ok(pb::OperationTarget {
                    role: target.role,
                    target: Some(target_ref),
                    generation_key: target.generation_key,
                    configuration_digest: target.configuration_digest,
                })
            })
            .collect::<Result<Vec<_>, RpcError>>()?;
        Ok(pb::OperationDetail {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id.clone(),
                kind: operation.operation_kind.clone(),
                state: operation.state.clone(),
                created_at: operation.created_at,
            }),
            targets,
            completed_units: u64::try_from(operation.progress_current).unwrap_or_default(),
            total_units: operation
                .progress_total
                .and_then(|value| u64::try_from(value).ok()),
            error: operation.error.clone().unwrap_or_default(),
            updated_at: operation
                .finished_at
                .or(operation.started_at)
                .unwrap_or(operation.created_at),
            finished_at: operation.finished_at,
            resource_version: operation.resource_version.to_string(),
            detail_json: operation.detail_json.clone(),
        })
    }
}
