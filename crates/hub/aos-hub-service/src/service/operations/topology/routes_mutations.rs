//! Routes mutations in the topology capability.

use super::*;

impl RpcService {
    /// Applies a route creation plan exactly once.
    pub async fn create_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRouteMutationRequest,
    ) -> Result<pb::RouteResponse, RpcError> {
        self.apply_route_mutation(auth, req, "create_route").await
    }

    /// Applies a route configuration update exactly once.
    pub async fn update_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRouteMutationRequest,
    ) -> Result<pb::RouteResponse, RpcError> {
        self.apply_route_mutation(auth, req, "update_route").await
    }

    /// Applies creation of a distinct replacement route exactly once.
    pub async fn replace_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRouteMutationRequest,
    ) -> Result<pb::RouteResponse, RpcError> {
        self.apply_route_mutation(auth, req, "replace_route").await
    }

    /// Applies route enable exactly once.
    pub async fn enable_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::RouteResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "enable_route",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            self.wake_route_probe_controller().await;
            return Ok(response);
        }
        self.apply_route_lifecycle(auth, req, "enable")
            .await?
            .map_err(|_| RpcError::internal(anyhow::anyhow!("enable returned delete response")))
    }

    /// Applies route disable exactly once.
    pub async fn disable_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::RouteResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "disable_route",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.apply_route_lifecycle(auth, req, "disable")
            .await?
            .map_err(|_| RpcError::internal(anyhow::anyhow!("disable returned delete response")))
    }

    /// Applies route deletion exactly once.
    pub async fn delete_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_route",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.apply_route_lifecycle(auth, req, "delete")
            .await?
            .err()
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("delete returned route response")))
    }

    /// Applies a route advertisement selection exactly once.
    pub async fn set_route_advertisement(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRouteAdvertisementRequest,
    ) -> Result<pb::RouteAdvertisementResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "set_route_advertisement",
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
            "set_route_advertisement",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, RouteAdvertisementPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "set_route_advertisement",
                Some(&req.confirmation_hash),
            )
            .await?;
        let surface = Self::route_surface_from_plan(&input.surface)?;
        let owner_scope_key = self.route_surface_owner_scope(surface).await?;
        self.require_delivery_scope(auth, &owner_scope_key, Permission::RouteManage)
            .await?;
        let record = self
            .db
            .set_route_advertisement(
                surface,
                &input.request.audience,
                &input.request.route_id,
                input.baseline_resource_version,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::RouteAdvertisementResponse {
            route_advertisement: Some(pb::RouteAdvertisement {
                surface: Some(self.route_surface_message(record.surface).await?),
                audience: record.audience,
                route_id: record.route_id,
                resource_version: record.resource_version.to_string(),
            }),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Queues controller observation of one exact enabled delivery-route generation.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, not-found, stale-version,
    /// disabled-route, or durable-scheduling error.
    pub async fn complete_route_probe(
        &self,
        auth: Option<&str>,
        req: pb::CompleteRouteProbeRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let claims = self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let route = self
            .db
            .route(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("route"))?;
        let owner_scope_key = self
            .db
            .topology_operation_target_scope("route", &route.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("route"))?;
        let scope = Scope::try_parse(&owner_scope_key)
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route has invalid owner scope")))?;
        if self
            .require_permission(&claims, Permission::RouteManage, &scope)
            .await
            .is_err()
        {
            return Err(RpcError::not_found("route"));
        }
        if req.expected_observation_version.is_empty()
            || parse_resource_version(&req.expected_observation_version, route.resource_version)?
                != route.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "route resource version is required and must be current".to_string(),
            ));
        }
        if !route.enabled {
            return Err(RpcError::FailedPrecondition(
                "disabled routes cannot be probed".to_string(),
            ));
        }
        let generation = route.configuration_generation.ok_or_else(|| {
            RpcError::FailedPrecondition("route has no selected configuration".to_string())
        })?;
        let configuration_digest = route.configuration_digest.ok_or_else(|| {
            RpcError::FailedPrecondition("route has no selected configuration digest".to_string())
        })?;
        let operation_id = hex::encode(Sha256::digest(
            format!(
                "delivery-route-probe-v1\0{}\0{}\0{}\0{}",
                route.id, generation, configuration_digest, req.controller_lease_id
            )
            .as_bytes(),
        ));
        let operation = self
            .topology_probes
            .schedule(
                &operation_id,
                crate::topology_probe::TopologyProbe::Route {
                    stable_id: route.id,
                    generation,
                    configuration_digest,
                },
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!("schedule delivery-route probe: {error:#}"))
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
