//! Delivery reads in the webhooks capability.

use super::*;

impl RpcService {
    /// `WebhookService.ListWebhooks` — an org's webhook subscriptions.
    ///
    /// Secrets are omitted. Requires [`Permission::MembersManage`] on the org
    /// scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `members.manage` on
    /// the org, [`RpcError::NotFound`] for an unknown org, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_webhooks(
        &self,
        auth: Option<&str>,
        req: pb::ListWebhooksRequest,
    ) -> Result<pb::ListWebhooksResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        let webhooks: Vec<pb::Webhook> = self
            .db
            .list_webhooks(org.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|w| pb::Webhook {
                id: w.id,
                org_slug: org.slug.clone(),
                url: w.url,
                events: w.events,
                active: w.active,
                created_at: w.created_at,
                resource_version: w.resource_version.to_string(),
                updated_at: w.updated_at,
                secret_version_ref: w.secret_version_ref,
                credential_fingerprint: w.credential_fingerprint,
            })
            .collect();
        let (webhooks, next_page_token) = paginate(webhooks, req.page_size, &req.page_token)?;
        Ok(pb::ListWebhooksResponse {
            webhooks,
            next_page_token,
            supported_event_types: crate::webhook::SUPPORTED_EVENT_TYPES
                .iter()
                .map(|event| (*event).to_string())
                .collect(),
        })
    }
}
