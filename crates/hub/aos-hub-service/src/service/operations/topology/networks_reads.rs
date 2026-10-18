//! Networks reads in the topology capability.

use super::*;

impl RpcService {
    /// Lists stable network-boundary identities in one owner scope.
    pub async fn list_network_policies(
        &self,
        auth: Option<&str>,
        req: pb::ListTopologyResourcesRequest,
    ) -> Result<pb::ListNetworkPoliciesResponse, RpcError> {
        self.require_delivery_scope(auth, &req.owner_scope_key, Permission::NetworkPolicyRead)
            .await?;
        let page = self
            .db
            .list_network_policies_page(
                &req.owner_scope_key,
                req.page_size,
                (!req.page_token.is_empty()).then_some(req.page_token.as_str()),
                req.include_granted,
            )
            .await
            .map_err(RpcError::internal)?;
        let mut network_policies = Vec::with_capacity(page.records.len());
        for record in page.records {
            network_policies.push(self.network_policy_message(record).await?);
        }
        Ok(pb::ListNetworkPoliciesResponse {
            network_policies,
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Returns one stable network-boundary identity.
    pub async fn get_network_policy(
        &self,
        auth: Option<&str>,
        req: pb::GetTopologyResourceRequest,
    ) -> Result<pb::NetworkPolicyResponse, RpcError> {
        let record = self
            .db
            .network_policy(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &record.owner_scope_key,
            Permission::NetworkPolicyRead,
            "network policy",
        )
        .await?;
        Ok(pb::NetworkPolicyResponse {
            network_policy: Some(self.network_policy_message(record).await?),
        })
    }

    /// Lists immutable revisions of one network policy.
    pub async fn list_network_policy_revisions(
        &self,
        auth: Option<&str>,
        req: pb::ListNetworkPolicyRevisionsRequest,
    ) -> Result<pb::ListNetworkPolicyRevisionsResponse, RpcError> {
        let boundary = self
            .db
            .network_policy(&req.boundary_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &boundary.owner_scope_key,
            Permission::NetworkPolicyRead,
            "network policy",
        )
        .await?;
        let cursor = if req.page_token.is_empty() {
            0
        } else {
            req.page_token
                .parse()
                .map_err(|_| RpcError::invalid("pageToken must be a revision integer"))?
        };
        let page = self
            .db
            .list_network_policy_revisions_page(&req.boundary_id, req.page_size, cursor)
            .await
            .map_err(RpcError::internal)?;
        let revisions = page
            .records
            .into_iter()
            .map(Self::network_policy_revision_message)
            .collect::<Result<_, _>>()?;
        Ok(pb::ListNetworkPolicyRevisionsResponse {
            revisions,
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Returns one immutable network-boundary revision.
    pub async fn get_network_policy_revision(
        &self,
        auth: Option<&str>,
        req: pb::GetNetworkPolicyRevisionRequest,
    ) -> Result<pb::NetworkPolicyRevisionResponse, RpcError> {
        let boundary = self
            .db
            .network_policy(&req.boundary_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &boundary.owner_scope_key,
            Permission::NetworkPolicyRead,
            "network policy",
        )
        .await?;
        let revision = self
            .db
            .network_policy_revision(&req.boundary_id, req.revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy revision"))?;
        Ok(pb::NetworkPolicyRevisionResponse {
            revision: Some(Self::network_policy_revision_message(revision)?),
            coordination_operation: None,
        })
    }
}
