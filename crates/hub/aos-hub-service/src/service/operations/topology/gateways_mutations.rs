//! Gateways mutations in the topology capability.

use super::*;

impl RpcService {
    /// Applies a gateway creation plan exactly once.
    pub async fn create_gateway(
        &self,
        auth: Option<&str>,
        req: pb::ApplyGatewayMutationRequest,
    ) -> Result<pb::GatewayResponse, RpcError> {
        self.apply_gateway_mutation(auth, req, false).await
    }

    /// Applies a gateway generation-update plan exactly once.
    pub async fn update_gateway(
        &self,
        auth: Option<&str>,
        req: pb::ApplyGatewayMutationRequest,
    ) -> Result<pb::GatewayResponse, RpcError> {
        self.apply_gateway_mutation(auth, req, true).await
    }

    /// Applies a gateway consumer-grant plan exactly once.
    pub async fn grant_gateway_scope(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        self.apply_gateway_scope_grant(auth, req, false).await
    }

    /// Applies a gateway consumer-grant revocation exactly once.
    pub async fn revoke_gateway_scope(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        self.apply_gateway_scope_grant(auth, req, true).await
    }

    /// Reconciles one exact desired gateway generation under CAS.
    pub async fn report_gateway(
        &self,
        auth: Option<&str>,
        req: pb::ReportGatewayRequest,
    ) -> Result<pb::GatewayResponse, RpcError> {
        self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let current = self
            .authorized_gateway(auth, &req.stable_id, Permission::GatewayManage)
            .await?;
        let expected = parse_resource_version(&req.expected_observation_version, 0)?;
        if expected <= 0 || expected != current.resource_version {
            return Err(RpcError::FailedPrecondition(
                "gateway resource version is required and must be current".to_string(),
            ));
        }
        let record = self
            .db
            .observe_gateway(
                &current.id,
                req.observed_generation,
                &req.state,
                (!req.error.is_empty()).then_some(req.error.as_str()),
                expected,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(pb::GatewayResponse {
            gateway: Some(self.gateway_message(record).await?),
        })
    }

    /// Applies a gateway enable plan exactly once.
    pub async fn enable_gateway(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::GatewayResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "enable_gateway",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.apply_gateway_lifecycle(auth, req, "enable")
            .await?
            .map_err(|_| RpcError::internal(anyhow::anyhow!("enable returned delete response")))
    }

    /// Applies a gateway disable plan exactly once.
    pub async fn disable_gateway(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::GatewayResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "disable_gateway",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.apply_gateway_lifecycle(auth, req, "disable")
            .await?
            .map_err(|_| RpcError::internal(anyhow::anyhow!("disable returned delete response")))
    }

    /// Applies gateway deletion exactly once.
    pub async fn delete_gateway(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_gateway",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.apply_gateway_lifecycle(auth, req, "delete")
            .await?
            .err()
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("delete returned gateway response")))
    }
}
