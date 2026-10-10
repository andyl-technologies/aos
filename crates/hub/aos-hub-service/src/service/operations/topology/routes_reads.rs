//! Routes reads in the topology capability.

use super::*;

impl RpcService {
    /// Lists authorized routes for one exact surface.
    pub async fn list_routes(
        &self,
        auth: Option<&str>,
        req: pb::ListRoutesRequest,
    ) -> Result<pb::ListRoutesResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let owner_scope_key = self.route_surface_owner_scope(surface).await?;
        self.require_delivery_scope(auth, &owner_scope_key, Permission::RouteRead)
            .await?;
        let page = self
            .db
            .list_routes_page(surface, req.page_size, &req.page_token)
            .await
            .map_err(RpcError::internal)?;
        let mut routes = Vec::with_capacity(page.records.len());
        for record in page.records {
            routes.push(self.route_message(record).await?);
        }
        Ok(pb::ListRoutesResponse {
            routes,
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Returns one authorized route by stable identity.
    pub async fn get_route(
        &self,
        auth: Option<&str>,
        req: pb::GetTopologyResourceRequest,
    ) -> Result<pb::RouteResponse, RpcError> {
        let route = self
            .authorized_route(auth, &req.stable_id, Permission::RouteRead)
            .await?;
        Ok(pb::RouteResponse {
            route: Some(self.route_message(route).await?),
        })
    }

    /// Explains route path matching and readiness without exposing private internals.
    pub async fn explain_route(
        &self,
        auth: Option<&str>,
        req: pb::ExplainRouteRequest,
    ) -> Result<pb::ExplainRouteResponse, RpcError> {
        let route = self
            .authorized_route(auth, &req.route_id, Permission::RouteRead)
            .await?;
        let snapshot = self
            .db
            .route_snapshot(&route.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("route configuration"))?;
        let machine_path = Self::normalize_route_base_path(&req.machine_path)?;
        let matches_path = snapshot.spec.base_path.is_empty()
            || machine_path == snapshot.spec.base_path
            || machine_path
                .strip_prefix(&snapshot.spec.base_path)
                .is_some_and(|suffix| suffix.starts_with('/'));
        let capability = match req.access_class.as_str() {
            "git" => snapshot.spec.serves_git,
            "nix_cache" => snapshot.spec.serves_cache,
            "web" => snapshot.spec.serves_web,
            "oci" => snapshot.spec.serves_oci,
            _ => {
                return Err(RpcError::invalid(
                    "accessClass must be git, nix_cache, web, or oci",
                ));
            }
        };
        let mut decisions = vec![format!("mode={}", snapshot.spec.mode)];
        let mut rejection_reasons = Vec::new();
        if route.enabled {
            decisions.push("route is enabled".to_string());
        } else {
            rejection_reasons.push("route is disabled".to_string());
        }
        if matches_path {
            decisions.push("machine path matches the route base path".to_string());
        } else {
            rejection_reasons.push("machine path is outside the route base path".to_string());
        }
        if capability {
            decisions.push(format!("route serves {}", req.access_class));
        } else {
            rejection_reasons.push(format!("route does not serve {}", req.access_class));
        }
        if snapshot.observation_state == "healthy" {
            decisions.push("current route generation is healthy".to_string());
        } else {
            rejection_reasons.push("current route generation is not healthy".to_string());
        }
        let endpoint_url = snapshot
            .canonical_url
            .strip_suffix(&snapshot.spec.base_path)
            .unwrap_or(&snapshot.canonical_url);
        Ok(pb::ExplainRouteResponse {
            normalized_url: format!("{endpoint_url}{machine_path}"),
            decisions,
            rejection_reasons,
        })
    }
}
