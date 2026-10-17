//! Exact logical-charge retirement after the existing empty-provider fences.

use anyhow::{Context as _, Result, ensure};

use crate::backend::CheckedStatement;

use super::Database;

impl Database {
    pub(crate) async fn mirror_usage_retirement_statements(
        &self,
        registry_id: i64,
        org_id: Option<i64>,
        now: i64,
    ) -> Result<(Vec<CheckedStatement>, Vec<CheckedStatement>)> {
        let totals = self.backend.query_opt(
            "SELECT COUNT(*), CAST(COALESCE(SUM(charge.accounted_bytes), 0) AS BIGINT),
                    CAST(COALESCE(SUM(CASE WHEN charge.accounted_bytes >= 0 AND charge.resource_version > 0
                      AND (charge.org_id = CAST(?2 AS BIGINT)
                        OR (charge.org_id IS NULL AND CAST(?2 AS BIGINT) IS NULL))
                      THEN 0 ELSE 1 END), 0) AS BIGINT)
               FROM surface_object_usage charge JOIN surface_objects object ON object.id = charge.surface_object_id
              WHERE object.registry_id = ?1",
            &vals![registry_id, org_id],
        ).await?.context("registry charge census disappeared")?;
        let objects: i64 = totals.get(0)?;
        let bytes: i64 = totals.get(1)?;
        let corrupt: i64 = totals.get(2)?;
        ensure!(
            objects >= 0 && bytes >= 0 && corrupt == 0,
            "registry charges are inconsistent"
        );

        let mut locks = Vec::new();
        let mut settlement = Vec::new();
        if let Some(org_id) = org_id {
            let usage = self.org_usage(org_id).await?;
            let remaining_bytes = usage
                .used_bytes
                .checked_sub(bytes)
                .context("registry charge refund overflow")?;
            let remaining_objects = usage
                .object_count
                .checked_sub(objects)
                .context("registry count refund overflow")?;
            ensure!(
                remaining_bytes >= 0 && remaining_objects >= 0,
                "registry charge refund would underflow"
            );
            locks.extend([
                CheckedStatement::exact(
                    "UPDATE orgs SET updated_at = updated_at WHERE id = ?1",
                    vals![org_id],
                    1,
                ),
                CheckedStatement::exact(
                    "UPDATE org_usage SET updated_at = updated_at WHERE org_id = ?1",
                    vals![org_id],
                    1,
                ),
            ]);
            settlement.push(CheckedStatement::exact(
                "UPDATE org_usage SET used_bytes = ?2, object_count = ?3, updated_at = ?4
                  WHERE org_id = ?1 AND used_bytes = ?5 AND object_count = ?6",
                vals![
                    org_id,
                    remaining_bytes,
                    remaining_objects,
                    now,
                    usage.used_bytes,
                    usage.object_count
                ],
                1,
            ));
        }
        // The caller already holds the registry and proves provider emptiness.
        // Lock every retained charge before checking the exact aggregate again.
        settlement.push(CheckedStatement::exact(
            "UPDATE surface_object_usage SET updated_at = updated_at WHERE surface_object_id IN
                (SELECT id FROM surface_objects WHERE registry_id = ?1)
              AND ?2 = (SELECT COUNT(*) FROM surface_object_usage charge
                JOIN surface_objects object ON object.id = charge.surface_object_id WHERE object.registry_id = ?1)
              AND ?3 = (SELECT CAST(COALESCE(SUM(charge.accounted_bytes), 0) AS BIGINT) FROM surface_object_usage charge
                JOIN surface_objects object ON object.id = charge.surface_object_id WHERE object.registry_id = ?1)",
            vals![registry_id, objects, bytes], u64::try_from(objects)?,
        ));
        settlement.push(CheckedStatement::exact(
            "DELETE FROM surface_object_usage WHERE surface_object_id IN
                (SELECT id FROM surface_objects WHERE registry_id = ?1)
              AND (org_id = CAST(?2 AS BIGINT) OR (org_id IS NULL AND CAST(?2 AS BIGINT) IS NULL))",
            vals![registry_id, org_id],
            u64::try_from(objects)?,
        ));
        Ok((locks, settlement))
    }
}
