//! Gateways plans in the topology capability.

use super::*;

impl RpcService {
    /// Plans creation of a gateway identity and immutable generation one.
    pub async fn plan_create_gateway(
        &self,
        auth: Option<&str>,
        req: pb::PlanGatewayMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_gateway_mutation(auth, req, false).await
    }

    /// Plans selection of a new immutable gateway generation.
    pub async fn plan_update_gateway(
        &self,
        auth: Option<&str>,
        req: pb::PlanGatewayMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_gateway_mutation(auth, req, true).await
    }

    /// Plans an explicit consumer grant on one exact gateway generation.
    pub async fn plan_grant_gateway_scope(
        &self,
        auth: Option<&str>,
        req: pb::PlanConsumerScopeGrantRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_gateway_scope_grant(auth, req, false).await
    }

    /// Plans revocation of an unpinned gateway-generation grant.
    pub async fn plan_revoke_gateway_scope(
        &self,
        auth: Option<&str>,
        req: pb::PlanConsumerScopeGrantRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_gateway_scope_grant(auth, req, true).await
    }

    /// Previews every current direct route pinned to the desired gateway generation.
    pub async fn preview_gateway_routes(
        &self,
        auth: Option<&str>,
        req: pb::GetTopologyResourceRequest,
    ) -> Result<pb::GatewayRoutePreviewResponse, RpcError> {
        let gateway = self
            .authorized_gateway(auth, &req.stable_id, Permission::GatewayRead)
            .await?;
        let generation = gateway.desired_generation.ok_or_else(|| {
            RpcError::FailedPrecondition("gateway has no desired generation".to_string())
        })?;
        let routes = self
            .db
            .gateway_route_preview(&gateway.id, generation)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|route| pb::GatewayRoutePreview {
                canonical_url: route.canonical_url,
                placement_name: route.placement_name,
                base_path: route.base_path,
                warnings: if gateway.enabled {
                    Vec::new()
                } else {
                    vec!["gateway is disabled".to_string()]
                },
            })
            .collect();
        Ok(pb::GatewayRoutePreviewResponse { routes })
    }

    /// Plans enabling a reconciled gateway.
    pub async fn plan_enable_gateway(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_gateway_lifecycle(auth, req, "enable").await
    }

    /// Plans disabling a gateway.
    pub async fn plan_disable_gateway(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_gateway_lifecycle(auth, req, "disable").await
    }

    /// Plans deletion of a disabled unreferenced gateway.
    pub async fn plan_delete_gateway(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_gateway_lifecycle(auth, req, "delete").await
    }
}
