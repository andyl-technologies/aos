//! Reuses independently committed evidence under an exact inventory and policy.
//!
//! Profile heads locate immutable evaluation closures. Their observations keep
//! their original times and completeness; reuse grants no renewed freshness or
//! disposition authority and performs no source or raw-body acquisition.

use anyhow::{bail, Context as _, Result};
use aos_assessment::input::EvaluationData;
use aos_assessment_runtime::cache::merge_committed_evidence;

use crate::db::{AssessmentScanRecord, Database};

impl Database {
    pub(super) async fn restore_assessment_committed_evidence(
        &self,
        scan: &AssessmentScanRecord,
        data: &mut EvaluationData,
    ) -> Result<()> {
        let rows = self
            .backend
            .query(
                "SELECT DISTINCT heads.last_scan_id, previous.generation
             FROM assessment_heads AS heads JOIN assessment_scans AS previous
               ON previous.scan_id = heads.last_scan_id AND previous.registry_id = heads.registry_id
             WHERE heads.registry_id = ?1 AND heads.inventory_digest = ?2
               AND heads.policy_digest = ?3 AND heads.committed_generation > 0
               AND previous.admission_complete = 1 AND previous.state IN('succeeded', 'partial')
               AND previous.generation < ?4
             ORDER BY previous.generation, heads.last_scan_id LIMIT 10001",
                &vals![@slice scan.registry_id, scan.request.inventory_digest.to_string(),
                scan.request.policy_digest.to_string(), scan.generation],
            )
            .await?;
        if rows.len() > 10_000 {
            bail!("committed assessment cache exceeds its closure count bound");
        }
        let mut read_bytes = 0_u64;
        let read_limit = scan.request.limits.normalized_bytes.min(64 * 1024 * 1024);
        for row in rows {
            let (input, retained) = self
                .assessment_frozen_evaluation(scan.registry_id, &row.get::<String>(0)?)
                .await?;
            if input.inventory_digest != scan.request.inventory_digest
                || input.policy_digest != scan.request.policy_digest
            {
                bail!("committed cache differs from the requested inventory or policy");
            }
            read_bytes = read_bytes
                .checked_add(super::objects::encode(&retained)?.len() as u64)
                .filter(|bytes| *bytes <= read_limit)
                .context("committed cache exceeds its normalized closure read allowance")?;
            merge_committed_evidence(data, retained)?;
            // Bound the accumulator as well as each retained source closure.
            super::objects::encode(data)?;
        }
        Ok(())
    }
}
