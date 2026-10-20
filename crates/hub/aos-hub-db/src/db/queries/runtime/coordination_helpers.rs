//! Coordination helpers in the runtime capability.

use super::*;

impl Database {
    pub(in crate::db) async fn system_image_delivery_ready(
        &self,
        registry_id: i64,
        delivery: &aos_registry_format::manifest::ImageDelivery,
    ) -> Result<bool> {
        if delivery.is_store_backed() {
            return Ok(true);
        }
        for (key, hash, size) in [
            (
                delivery.object_key.as_str(),
                delivery.sha256.as_str(),
                delivery.byte_size,
            ),
            (
                delivery.artifact_contract.document.object_key.as_str(),
                delivery.artifact_contract.document.sha256.as_str(),
                delivery.artifact_contract.document.byte_size,
            ),
        ] {
            let size =
                i64::try_from(size).context("signed image object size exceeds database range")?;
            let present = self
                .backend
                .query_opt(
                    "SELECT 1 FROM registry_image_roots root
                     JOIN surface_objects object ON object.id = root.surface_object_id
                     JOIN object_placements presence
                       ON presence.surface_object_id = object.id
                      AND presence.registry_id = object.registry_id
                     JOIN surface_placement_effective placement
                       ON placement.id = presence.placement_id
                      AND placement.registry_id = object.registry_id
                     WHERE root.registry_id = ?1 AND object.object_key = ?2
                       AND root.expected_hash = ?3 AND root.expected_size = ?4
                       AND presence.state = 'present'
                       AND presence.observed_hash = ?3 AND presence.observed_size = ?4
                       AND placement.kind = 'complete'
                       AND placement.desired_state = 'active'
                       AND placement.state IN ('ready', 'degraded')
                       AND placement.effective_read_enabled = 1
                     LIMIT 1",
                    &vals![registry_id, key, hash, size],
                )
                .await?
                .is_some();
            if !present {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(in crate::db) async fn revoke_refresh_family(
        &self,
        family_id: &str,
        now: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE refresh_token_families SET revoked_at = ?2
                 WHERE id = ?1 AND revoked_at IS NULL",
                &vals![family_id, now],
            )
            .await?;
        Ok(())
    }

    /// Reloads current delivery and webhook configuration after winning a claim.
    pub(in crate::db) async fn delivery_for_claim(
        &self,
        id: i64,
        claim_token: &str,
    ) -> Result<Option<DueDelivery>> {
        let row = self
            .backend
            .query_opt(
                "SELECT d.id, d.delivery_id, d.webhook_id, d.event, d.payload, d.attempts, w.url,
                        w.secret_version_ref, w.credential_fingerprint
                   FROM webhook_deliveries d
                   JOIN webhooks w ON w.id = d.webhook_id
                  WHERE d.id = ?1 AND d.claim_token = ?2",
                &vals![id, claim_token],
            )
            .await?;
        row.map(|row| {
            let payload: String = row.get(4)?;
            anyhow::ensure!(
                payload.len() <= 1024 * 1024,
                "webhook delivery payload exceeds limit"
            );
            Ok(DueDelivery {
                id: row.get(0)?,
                delivery_id: row.get(1)?,
                claim_token: claim_token.to_string(),
                webhook_id: row.get(2)?,
                event: row.get(3)?,
                payload,
                attempts: row.get(5)?,
                url: row.get(6)?,
                secret_version_ref: row.get(7)?,
                credential_fingerprint: row.get(8)?,
            })
        })
        .transpose()
    }
}
