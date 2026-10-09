//! Placements reads in the topology capability.

use super::*;

impl RpcService {
    /// `TopologyService.ListPlacements` — lists physical placements by stable name.
    ///
    /// Registry visibility and cache visibility use their existing read gates;
    /// private surfaces therefore require the same bearer authority as their
    /// other public read APIs.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::InvalidArgument`] for a missing surface or malformed
    /// page token, the surface's usual authentication/authorization errors,
    /// [`RpcError::NotFound`] for an unknown surface, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_placements(
        &self,
        auth: Option<&str>,
        req: pb::ListPlacementsRequest,
    ) -> Result<pb::ListPlacementsResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let records = self
            .db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?;
        let mut placements = Vec::with_capacity(records.len());
        for record in records {
            placements.push(self.placement_message(record).await?);
        }
        let (placements, next_page_token) = paginate(placements, req.page_size, &req.page_token)?;
        Ok(pb::ListPlacementsResponse {
            placements,
            next_page_token,
        })
    }

    /// `TopologyService.GetPlacement` — reads one placement by surface-local name.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::InvalidArgument`] for a missing surface or empty
    /// placement name, the surface's usual authentication/authorization errors,
    /// [`RpcError::NotFound`] for an unknown surface or placement, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_placement(
        &self,
        auth: Option<&str>,
        req: pb::GetPlacementRequest,
    ) -> Result<pb::GetPlacementResponse, RpcError> {
        if req.name.is_empty() {
            return Err(RpcError::invalid("placement name must not be empty"));
        }
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let placement = self
            .db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|placement| placement.name == req.name)
            .ok_or_else(|| RpcError::not_found("placement"))?;
        Ok(pb::GetPlacementResponse {
            placement: Some(self.placement_message(placement).await?),
        })
    }

    /// Lists placement-policy identities for one surface.
    pub async fn list_placement_policies(
        &self,
        auth: Option<&str>,
        req: pb::SurfaceListRequest,
    ) -> Result<pb::ListPlacementPoliciesResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let records = self
            .db
            .list_placement_policy_identities(surface)
            .await
            .map_err(RpcError::internal)?;
        let mut policies = Vec::with_capacity(records.len());
        for record in records {
            policies.push(self.placement_policy_message(record).await?);
        }
        let (policies, next_page_token) = paginate(policies, req.page_size, &req.page_token)?;
        Ok(pb::ListPlacementPoliciesResponse {
            policies,
            next_page_token,
        })
    }

    /// Returns one placement-policy identity on an exact surface.
    pub async fn get_placement_policy(
        &self,
        auth: Option<&str>,
        req: pb::GetPlacementPolicyRequest,
    ) -> Result<pb::PlacementPolicyResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let identity = self
            .db
            .placement_policy_identity(&req.policy_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|identity| identity.surface == surface)
            .ok_or_else(|| RpcError::not_found("placement policy"))?;
        Ok(pb::PlacementPolicyResponse {
            policy: Some(self.placement_policy_message(identity).await?),
        })
    }

    /// Lists immutable revisions of one placement-policy identity.
    pub async fn list_placement_policy_revisions(
        &self,
        auth: Option<&str>,
        req: pb::ListPlacementPolicyRevisionsRequest,
    ) -> Result<pb::ListPlacementPolicyRevisionsResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let identity = self
            .db
            .placement_policy_identity(&req.policy_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|identity| identity.surface == surface)
            .ok_or_else(|| RpcError::not_found("placement policy"))?;
        let records = self
            .db
            .list_placement_policy_revisions(&identity.id)
            .await
            .map_err(RpcError::internal)?;
        let mut revisions = Vec::with_capacity(records.len());
        for record in records {
            revisions.push(self.placement_policy_revision_message(record).await?);
        }
        let (revisions, next_page_token) = paginate(revisions, req.page_size, &req.page_token)?;
        Ok(pb::ListPlacementPolicyRevisionsResponse {
            revisions,
            next_page_token,
        })
    }

    /// Returns one numbered immutable placement-policy revision.
    pub async fn get_placement_policy_revision(
        &self,
        auth: Option<&str>,
        req: pb::GetPlacementPolicyRevisionRequest,
    ) -> Result<pb::PlacementPolicyRevisionResponse, RpcError> {
        if req.revision <= 0 {
            return Err(RpcError::invalid("revision must be positive"));
        }
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let identity = self
            .db
            .placement_policy_identity(&req.policy_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|identity| identity.surface == surface)
            .ok_or_else(|| RpcError::not_found("placement policy"))?;
        let revision = self
            .db
            .list_placement_policy_revisions(&identity.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|revision| revision.revision == req.revision)
            .ok_or_else(|| RpcError::not_found("placement policy revision"))?;
        Ok(pb::PlacementPolicyRevisionResponse {
            revision: Some(self.placement_policy_revision_message(revision).await?),
        })
    }

    /// Lists operator-confirmed placement equivalences for one surface.
    pub async fn list_placement_equivalences(
        &self,
        auth: Option<&str>,
        req: pb::SurfaceListRequest,
    ) -> Result<pb::ListPlacementEquivalencesResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let records = self
            .db
            .list_placement_equivalences(surface)
            .await
            .map_err(RpcError::internal)?;
        let mut equivalences = Vec::with_capacity(records.len());
        for record in records {
            equivalences.push(self.placement_equivalence_message(record).await?);
        }
        let (equivalences, next_page_token) =
            paginate(equivalences, req.page_size, &req.page_token)?;
        Ok(pb::ListPlacementEquivalencesResponse {
            equivalences,
            next_page_token,
        })
    }
}
