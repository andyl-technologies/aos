//! Operations mutations in the topology capability.

use super::*;

impl RpcService {
    /// Applies an instance topology-default replacement plan.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, stale-plan, or persistence error.
    pub async fn apply_set_instance_topology_defaults(
        &self,
        auth: Option<&str>,
        req: pb::ApplySetTopologyDefaultsRequest,
    ) -> Result<pb::TopologyDefaultsResponse, RpcError> {
        self.apply_set_topology_defaults(auth, req, true).await
    }

    /// Applies an organization topology-default replacement plan.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, stale-plan, or persistence error.
    pub async fn apply_set_organization_topology_defaults(
        &self,
        auth: Option<&str>,
        req: pb::ApplySetTopologyDefaultsRequest,
    ) -> Result<pb::TopologyDefaultsResponse, RpcError> {
        self.apply_set_topology_defaults(auth, req, false).await
    }
}
