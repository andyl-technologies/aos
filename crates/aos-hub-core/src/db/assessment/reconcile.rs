//! Bounded recovery of superseded, exhausted and cancelled durable scan work.
//!
//! Recovery settles execution state without publishing assessments or refunding
//! quota. Live physical reservations remain fenced until their deadlines.

use anyhow::{bail, Result};

use crate::db::Database;

impl Database {
    /// Settles one authorized registry's bounded active-scan page.
    ///
    /// The installed controller independently authorizes the registry. Recovery
    /// grants no execution authority and preserves committed profile heads.
    /// The returned last scan is an exclusive continuation; a complete pass
    /// restarts from the empty cursor to recover concurrent admissions.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, corrupt requests or persistence.
    pub async fn reconcile_assessment_scans(
        &self,
        registry_id: i64,
        after_scan: &str,
        limit: u32,
    ) -> Result<Option<String>> {
        if !(1..=100).contains(&limit)
            || after_scan.len() > 128
            || after_scan.chars().any(char::is_control)
        {
            bail!("assessment recovery exceeds its bounded registry page");
        }
        let rows = self
            .backend
            .query(
                "SELECT scan_id FROM assessment_scans WHERE registry_id = ?1 AND scan_id > ?2
             AND state IN('queued', 'running', 'cancelling') ORDER BY scan_id LIMIT ?3",
                &vals![@slice registry_id, after_scan, limit],
            )
            .await?;
        let clock = self.backend.dialect().unix_time_expression();
        for row in &rows {
            let scan_id: String = row.get(0)?;
            let Some(scan) = self.assessment_scan(registry_id, &scan_id).await? else {
                continue;
            };
            self.backend.execute(&format!(
                "UPDATE assessment_scans SET state = 'superseded', last_error_code = 'scan-scope-superseded',
                     claim_token = NULL, lease_expires_at = NULL, completed_at = {clock}, updated_at = {clock},
                     resource_version = resource_version + 1
                 WHERE registry_id = ?1 AND scan_id = ?2 AND resource_version = ?3 AND state IN('queued', 'running')
                   AND (NOT EXISTS(SELECT 1 FROM assessment_resources resource WHERE resource.registry_id = ?1
                         AND resource.partition_key = assessment_scans.partition_key
                         AND resource.inventory_digest = assessment_scans.inventory_digest
                         AND resource.inventory_revision = assessment_scans.inventory_revision
                         AND resource.policy_digest = assessment_scans.policy_digest
                         AND resource.authorization_revision = assessment_scans.authorization_revision)
                     OR EXISTS(SELECT 1 FROM assessment_scan_targets target
                         LEFT JOIN assessment_heads head ON head.registry_id = ?1
                           AND head.inventory_digest = assessment_scans.inventory_digest
                           AND head.subject_ref = target.subject_ref AND head.profile = target.profile
                           AND head.policy_digest = assessment_scans.policy_digest
                         WHERE target.scan_id = ?2 AND (head.desired_generation IS NULL
                             OR head.desired_generation <> assessment_scans.generation)))"
            ), &vals![@slice registry_id, scan_id, scan.resource_version]).await?;
            let deadline =
                scan.created_at.unix_seconds() + u64::from(scan.request.limits.wall_seconds);
            self.backend.execute(&format!(
                "UPDATE assessment_scans SET state = 'failed', last_error_code = CASE
                         WHEN ?4 <= {clock} THEN 'operation-wall-time-exhausted'
                         WHEN EXISTS(SELECT 1 FROM assessment_scan_authorities authority
                             WHERE authority.scan_id = ?2 AND authority.registry_id = ?1 AND authority.expires_at <= {clock})
                           THEN 'job-authority-expired' ELSE 'operation-attempts-exhausted' END,
                     claim_token = NULL, lease_expires_at = NULL, completed_at = {clock}, updated_at = {clock},
                     resource_version = resource_version + 1
                 WHERE registry_id = ?1 AND scan_id = ?2 AND resource_version = ?3 AND state IN('queued', 'running')
                   AND (?4 <= {clock} OR EXISTS(SELECT 1 FROM assessment_scan_authorities authority
                         WHERE authority.scan_id = ?2 AND authority.registry_id = ?1 AND authority.expires_at <= {clock})
                     OR (attempt >= 100 AND (lease_expires_at IS NULL OR lease_expires_at <= {clock})))"
            ), &vals![@slice registry_id, scan_id, scan.resource_version, deadline]).await?;
            self.settle_assessment_scan_cancellation(registry_id, &scan_id)
                .await?;
        }
        let children = self.backend.query(&format!(
            "SELECT task.scan_id, task.task_id FROM assessment_tasks task
             JOIN assessment_scans scan ON scan.scan_id = task.scan_id
             WHERE scan.registry_id = ?1 AND scan.state IN('failed', 'superseded', 'cancelled')
               AND (task.state IN('pending', 'waiting') OR (task.state = 'leased'
                   AND (task.lease_expires_at <= {clock} OR EXISTS(SELECT 1 FROM assessment_budget_reservations reservation
                       WHERE reservation.reservation_id = task.reservation_id AND reservation.deadline <= {clock}))))
             ORDER BY task.scan_id, task.task_id LIMIT ?2"
        ), &vals![@slice registry_id, limit]).await?;
        for row in children {
            self.backend.execute(&format!(
                "UPDATE assessment_tasks SET state = 'cancelled', claim_token = NULL, lease_expires_at = NULL,
                     resource_version = resource_version + 1
                 WHERE scan_id = ?1 AND task_id = ?2
                   AND EXISTS(SELECT 1 FROM assessment_scans scan WHERE scan.scan_id = ?1
                       AND scan.registry_id = ?3 AND scan.state IN('failed', 'superseded', 'cancelled'))
                   AND (state IN('pending', 'waiting') OR (state = 'leased'
                     AND (lease_expires_at <= {clock} OR EXISTS(SELECT 1 FROM assessment_budget_reservations reservation
                         WHERE reservation.reservation_id = assessment_tasks.reservation_id AND reservation.deadline <= {clock}))))"
            ), &vals![@slice row.get::<String>(0)?, row.get::<String>(1)?, registry_id]).await?;
        }
        rows.last().map(|row| row.get(0)).transpose()
    }
}
