//! Operations reads in the topology capability.

use super::*;

impl RpcService {
    /// Returns instance topology defaults.
    pub async fn get_instance_topology_defaults(
        &self,
        auth: Option<&str>,
        _req: pb::GetInstanceTopologyDefaultsRequest,
    ) -> Result<pb::TopologyDefaultsResponse, RpcError> {
        self.writable_storage_owner(auth, "instance").await?;
        let defaults = self
            .db
            .stable_topology_defaults("instance")
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::TopologyDefaultsResponse {
            defaults: Some(Self::topology_defaults_or_empty("instance", defaults)),
        })
    }

    /// Returns organization topology defaults.
    pub async fn get_organization_topology_defaults(
        &self,
        auth: Option<&str>,
        req: pb::GetOrganizationTopologyDefaultsRequest,
    ) -> Result<pb::TopologyDefaultsResponse, RpcError> {
        let scope_key = self.org_or_not_found(&req.org_slug).await?.stable_id;
        self.writable_storage_owner(auth, &scope_key).await?;
        let defaults = self
            .db
            .stable_topology_defaults(&scope_key)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::TopologyDefaultsResponse {
            defaults: Some(Self::topology_defaults_or_empty(&scope_key, defaults)),
        })
    }
}
