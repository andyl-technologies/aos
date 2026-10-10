//! Routes plans in the topology capability.

use super::*;

impl RpcService {
    /// Plans creation of a disabled or enabled route.
    pub async fn plan_create_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanRouteMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_route_mutation(auth, req, false, None).await
    }

    /// Plans a byte-stable route configuration update.
    pub async fn plan_update_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanRouteMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_route_mutation(auth, req, true, None).await
    }

    /// Plans a distinct disabled successor for a URL-identity replacement.
    pub async fn plan_replace_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanReplaceRouteRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let predecessor = self
            .authorized_route(auth, &req.predecessor_route_id, Permission::RouteManage)
            .await?;
        if parse_resource_version(&req.expected_resource_version, 0)?
            != predecessor.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "predecessor route resource version is stale".to_string(),
            ));
        }
        if !predecessor.enabled {
            return Err(RpcError::FailedPrecondition(
                "predecessor route must be enabled before replacement".to_string(),
            ));
        }
        if req.spec.as_ref().is_some_and(|spec| spec.enabled) {
            return Err(RpcError::invalid(
                "replacement routes must be created disabled",
            ));
        }
        let mutation = pb::PlanRouteMutationRequest {
            stable_id: req.stable_id,
            spec: req.spec,
            expected_resource_version: String::new(),
            idempotency_key: req.idempotency_key,
            update_mask: Vec::new(),
        };
        self.plan_route_mutation(auth, mutation, false, Some(req.predecessor_route_id))
            .await
    }

    /// Plans enabling a route.
    pub async fn plan_enable_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_route_lifecycle(auth, req, "enable").await
    }

    /// Plans disabling a route.
    pub async fn plan_disable_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_route_lifecycle(auth, req, "disable").await
    }

    /// Plans deletion of a disabled, unreferenced route.
    pub async fn plan_delete_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_route_lifecycle(auth, req, "delete").await
    }

    /// Plans a surface/audience route advertisement selection under exact CAS.
    pub async fn plan_set_route_advertisement(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanRouteAdvertisementRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let (surface, owner_scope_key) = self
            .managed_route_surface(auth, req.surface.clone())
            .await?;
        if !matches!(req.audience.as_str(), "git" | "nix_cache" | "web") {
            return Err(RpcError::invalid("audience must be git, nix_cache, or web"));
        }
        let route = self
            .authorized_route(auth, &req.route_id, Permission::RouteManage)
            .await?;
        if route.surface != surface || !route.enabled {
            return Err(RpcError::FailedPrecondition(
                "route advertisement must be enabled on the same surface".to_string(),
            ));
        }
        let current = self
            .db
            .route_advertisement(surface, &req.audience)
            .await
            .map_err(RpcError::internal)?;
        let baseline_resource_version = current.as_ref().map(|record| record.resource_version);
        match (current.as_ref(), req.expected_resource_version.is_empty()) {
            (None, true) => {}
            (None, false) => {
                return Err(RpcError::invalid(
                    "new canonical selections forbid expectedResourceVersion",
                ));
            }
            (Some(record), false)
                if parse_resource_version(&req.expected_resource_version, 0)?
                    == record.resource_version => {}
            (Some(_), _) => {
                return Err(RpcError::FailedPrecondition(
                    "route advertisement resource version is required and must be current"
                        .to_string(),
                ));
            }
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = RouteAdvertisementPlanInput {
            request: req,
            surface: Self::route_surface_plan_seal(surface),
            baseline_resource_version,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "set_route_advertisement",
            &owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "select route '{}' as canonical {}",
                input.request.route_id, input.request.audience
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }
}
