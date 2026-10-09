//! Delivery reads in the webhooks capability.

use super::*;

impl Database {
    /// List an org's webhook subscriptions, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_webhooks(&self, org_id: i64) -> Result<Vec<WebhookRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, org_id, url, secret_version_ref, credential_fingerprint,
                        events, active, created_at, resource_version, updated_at
             FROM webhooks WHERE org_id = ?1 ORDER BY id",
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_webhook).collect()
    }
}
