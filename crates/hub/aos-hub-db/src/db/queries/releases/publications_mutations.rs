//! Publications mutations in the releases capability.

use super::*;

impl Database {
    /// Releases one exact in-flight snapshot lease without affecting peers.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn release_image_snapshot_lease(&self, lease_id: &str) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM image_snapshot_leases WHERE lease_id = ?1",
                &vals![lease_id],
            )
            .await?
            == 1)
    }

    /// Releases an exact set of in-flight snapshot leases atomically.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn release_image_snapshot_leases(&self, lease_ids: &[String]) -> Result<()> {
        if lease_ids.is_empty() {
            return Ok(());
        }
        let statements = lease_ids
            .iter()
            .map(|lease_id| {
                Statement::new(
                    "DELETE FROM image_snapshot_leases WHERE lease_id = ?1",
                    vals![lease_id].to_vec(),
                )
            })
            .collect::<Vec<_>>();
        self.backend.batch(&statements).await
    }

    /// Releases an exact domain claim and completes its plan atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when ownership or revision changed or persistence fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_org_domain_release_plan(
        &self,
        record: &OrgDomainRecord,
        scope: &str,
        plan_id: &str,
        apply_idempotency_key: &str,
        result_json: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        audit_event_id: &str,
    ) -> Result<()> {
        let mutation = Statement::new(
            "DELETE FROM org_domains
              WHERE domain = ?1 AND org_id = ?2 AND resource_version = ?3
                AND (incarnation_id = ?4
                     OR (incarnation_id IS NULL AND ?4 IS NULL))",
            vals![
                record.domain,
                record.org_id,
                record.resource_version,
                record.incarnation_id
            ],
        )
        .expecting(1);
        self.apply_org_domain_mutation_plan(
            mutation,
            "domain.release",
            &record.domain,
            scope,
            plan_id,
            apply_idempotency_key,
            result_json,
            actor_kind,
            actor_id,
            actor_label,
            audit_event_id,
        )
        .await
    }
}
