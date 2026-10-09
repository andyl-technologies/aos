//! Configuration helpers in the administration capability.

use super::*;

impl RpcService {
    pub(in crate::service) fn delivery_boundary_revision_plan_seal(
        record: crate::db::NetworkPolicyRevisionRecord,
    ) -> DeliveryBoundaryRevisionPlanSeal {
        DeliveryBoundaryRevisionPlanSeal {
            boundary_id: record.boundary_id,
            revision: record.revision,
            content_digest: record.content_digest,
            observation_state: record.observation_state,
            observed_at: record.observed_at,
            lifecycle_state: record.lifecycle_state,
            consumer_version: record.consumer_version,
            resource_version: record.resource_version,
        }
    }

    pub(in crate::service) async fn create_control_plan<T: serde::Serialize>(
        &self,
        claims: &Claims,
        plan_kind: &str,
        scope: &str,
        input: &T,
        idempotency_key: &str,
        effects: Vec<String>,
        warnings: Vec<String>,
        confirmation_hash: Option<String>,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        if idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let candidate_plan_id = uuid::Uuid::new_v4().to_string();
        let expires_at = clock::now_unix_secs() + TOPOLOGY_PLAN_TTL_SECS;
        let plan = self
            .db
            .create_topology_plan(&crate::db::NewTopologyPlan {
                plan_id: candidate_plan_id,
                plan_kind: plan_kind.to_string(),
                actor_kind: claims.owner_kind.clone(),
                actor_id: Some(claims.owner_id),
                actor_label: claims.sub.clone(),
                scope: scope.to_string(),
                input_versions_json: serde_json::to_string(input).map_err(RpcError::internal)?,
                effects_json: serde_json::to_string(&effects).map_err(RpcError::internal)?,
                warnings_json: serde_json::to_string(&warnings).map_err(RpcError::internal)?,
                confirmation_hash: confirmation_hash.clone(),
                request_idempotency_key: Some(idempotency_key.to_string()),
                expires_at,
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Self::control_plan_response(plan)
    }

    pub(in crate::service) async fn replayed_control_plan_input<T: serde::de::DeserializeOwned>(
        &self,
        claims: &Claims,
        plan_kind: &str,
        idempotency_key: &str,
    ) -> Result<Option<(crate::db::TopologyPlanRecord, T)>, RpcError> {
        if idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let Some(plan) = self
            .db
            .topology_plan_for_request(
                &claims.owner_kind,
                Some(claims.owner_id),
                plan_kind,
                idempotency_key,
            )
            .await
            .map_err(RpcError::internal)?
        else {
            return Ok(None);
        };
        let input = serde_json::from_str(&plan.input_versions_json).map_err(RpcError::internal)?;
        Ok(Some((plan, input)))
    }

    pub(in crate::service) fn control_plan_response(
        plan: crate::db::TopologyPlanRecord,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let effects = serde_json::from_str(&plan.effects_json).map_err(RpcError::internal)?;
        let warnings = serde_json::from_str(&plan.warnings_json).map_err(RpcError::internal)?;
        let input_value: serde_json::Value =
            serde_json::from_str(&plan.input_versions_json).map_err(RpcError::internal)?;
        let mut input_versions = Vec::new();
        collect_plan_input_versions(&input_value, "", &mut input_versions);
        input_versions.sort();
        input_versions.dedup();
        let mut pin_impacts = BTreeMap::new();
        collect_plan_pin_impacts(&input_value, &mut pin_impacts);
        Ok(pb::TopologyPlanResponse {
            plan: Some(pb::TopologyPlan {
                plan_id: plan.plan_id,
                expires_at: plan.expires_at,
                input_versions,
                effects,
                warnings,
                confirmation_hash: plan.confirmation_hash.unwrap_or_default(),
                pin_impacts: pin_impacts.into_values().collect(),
            }),
        })
    }

    pub(in crate::service) async fn load_control_plan<T: serde::de::DeserializeOwned>(
        &self,
        auth: Option<&str>,
        plan_id: &str,
        plan_kind: &str,
        confirmation_hash: Option<&str>,
    ) -> Result<(crate::db::TopologyPlanRecord, T), RpcError> {
        let claims = self.require_claims(auth)?;
        let plan = self
            .db
            .topology_plan(plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("topology plan"))?;
        if plan.plan_kind != plan_kind
            || plan.actor_kind != claims.owner_kind
            || plan.actor_id != Some(claims.owner_id)
            || plan.applied_at.is_some()
            || (plan.expires_at < clock::now_unix_secs() && plan.apply_idempotency_key.is_none())
        {
            return Err(RpcError::FailedPrecondition(
                "plan is expired, consumed, or belongs to another actor/operation".to_string(),
            ));
        }
        if let Some(expected) = plan.confirmation_hash.as_deref() {
            if confirmation_hash != Some(expected) {
                return Err(RpcError::FailedPrecondition(
                    "confirmation hash does not match the reviewed plan".to_string(),
                ));
            }
        }
        let input = serde_json::from_str(&plan.input_versions_json).map_err(RpcError::internal)?;
        Ok((plan, input))
    }

    pub(in crate::service) async fn begin_control_plan_apply(
        &self,
        auth: Option<&str>,
        plan_id: &str,
        plan_kind: &str,
        idempotency_key: &str,
        confirmation_hash: Option<&str>,
    ) -> Result<(), RpcError> {
        if idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let claims = self.require_claims(auth)?;
        let plan = self
            .db
            .topology_plan(plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("topology plan"))?;
        if plan.plan_kind != plan_kind
            || plan.actor_kind != claims.owner_kind
            || plan.actor_id != Some(claims.owner_id)
            || plan.applied_at.is_some()
        {
            return Err(RpcError::FailedPrecondition(
                "plan is consumed or belongs to another actor/operation".to_string(),
            ));
        }
        if plan.expires_at < clock::now_unix_secs()
            && plan.apply_idempotency_key.as_deref() != Some(idempotency_key)
        {
            return Err(RpcError::FailedPrecondition(
                "plan expired before apply began".to_string(),
            ));
        }
        if let Some(expected) = plan.confirmation_hash.as_deref() {
            if confirmation_hash != Some(expected) {
                return Err(RpcError::FailedPrecondition(
                    "confirmation hash does not match the reviewed plan".to_string(),
                ));
            }
        }
        self.db
            .begin_topology_plan_apply(plan_id, idempotency_key)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))
    }

    pub(in crate::service) async fn complete_control_plan<T: serde::Serialize>(
        &self,
        plan_id: &str,
        idempotency_key: &str,
        response: &T,
    ) -> Result<(), RpcError> {
        let result_json = serde_json::to_string(response).map_err(RpcError::internal)?;
        self.db
            .complete_topology_plan_apply(
                plan_id,
                idempotency_key,
                &result_json,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))
    }
}
