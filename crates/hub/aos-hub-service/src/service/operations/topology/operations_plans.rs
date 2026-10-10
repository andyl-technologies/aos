//! Operations plans in the topology capability.

use super::*;

impl RpcService {
    /// Plans instance topology defaults.
    pub async fn plan_set_instance_topology_defaults(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetTopologyDefaultsRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_set_topology_defaults(auth, req, true).await
    }

    /// Plans organization topology defaults.
    pub async fn plan_set_organization_topology_defaults(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetTopologyDefaultsRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_set_topology_defaults(auth, req, false).await
    }
}
