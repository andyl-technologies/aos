//! Bindings reads in the topology capability.

use super::*;

impl RpcService {
    /// `BindingService.GetBinding` reads one typed binding reference.
    ///
    /// # Errors
    ///
    /// Returns an authorization, malformed-reference, not-found, or persistence error.
    pub async fn get_binding_v1(
        &self,
        auth: Option<&str>,
        req: pb::GetBindingRequest,
    ) -> Result<pb::GetBindingResponse, RpcError> {
        let record = self.resolve_binding_reference(auth, req.binding).await?;
        Ok(pb::GetBindingResponse {
            binding: Some(self.binding_message(record).await?),
        })
    }

    /// Lists write revisions with bounded cursor pagination.
    pub async fn list_binding_write_revisions(
        &self,
        auth: Option<&str>,
        req: pb::ListBindingWriteRevisionsRequest,
    ) -> Result<pb::ListBindingWriteRevisionsResponse, RpcError> {
        let binding = self.resolve_binding_reference(auth, req.binding).await?;
        let stable_id = binding.stable_id.clone();
        let records = self
            .db
            .list_binding_write_revisions(binding.id)
            .await
            .map_err(RpcError::internal)?;
        let mut revisions = Vec::with_capacity(records.len());
        for revision in records {
            revisions.push(
                self.binding_write_revision_message(&stable_id, revision)
                    .await?,
            );
        }
        let (revisions, next_page_token) = paginate(revisions, req.page_size, &req.page_token)?;
        Ok(pb::ListBindingWriteRevisionsResponse {
            revisions,
            next_page_token,
        })
    }

    /// Gets one immutable write revision.
    pub async fn get_binding_write_revision(
        &self,
        auth: Option<&str>,
        req: pb::GetBindingWriteRevisionRequest,
    ) -> Result<pb::BindingWriteRevisionResponse, RpcError> {
        let binding = self.resolve_binding_reference(auth, req.binding).await?;
        let revision = self
            .db
            .binding_write_revision(binding.id, req.revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding write revision"))?;
        Ok(pb::BindingWriteRevisionResponse {
            revision: Some(
                self.binding_write_revision_message(&binding.stable_id, revision)
                    .await?,
            ),
        })
    }
}
