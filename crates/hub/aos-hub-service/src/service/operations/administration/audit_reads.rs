//! Audit reads in the administration capability.

use super::*;

impl RpcService {
    /// `AuditService.ListAudit` — recent audit entries at a scope, newest first.
    ///
    /// The caller must hold [`Permission::AuditRead`] (admin+) on the queried
    /// scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `audit.read` on the
    /// scope, [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_audit(
        &self,
        auth: Option<&str>,
        req: pb::ListAuditRequest,
    ) -> Result<pb::ListAuditResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope)?;
        self.require_permission(&claims, Permission::AuditRead, &scope)
            .await?;
        let entries: Vec<pb::AuditEntry> = self
            .db
            .list_audit(&req.scope)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|row| pb::AuditEntry {
                change_id: row.change_id.unwrap_or_default(),
                actor_label: row.actor_label,
                action: row.action,
                scope: row.scope,
                result_commit: row.result_commit.unwrap_or_default(),
                result_tag: row.result_tag.unwrap_or_default(),
                detail: row.detail.unwrap_or_default(),
                created_at: row.created_at,
            })
            .collect();
        let (entries, next_page_token) = paginate(entries, req.page_size, &req.page_token)?;
        Ok(pb::ListAuditResponse {
            entries,
            next_page_token,
        })
    }
}
