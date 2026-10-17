//! Finite immutable scan-list captures shared by SQL and HubDb deployments.

use anyhow::{bail, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::control::{ScanListV1, ScanSummary};
use aos_assessment_runtime::read_snapshot::{
    parse_scan_cursor, ScanPageError, ScanReadSnapshotV1, SCAN_READ_SNAPSHOT_V1,
};

use super::AssessmentObjectKind;
use crate::db::Database;

impl Database {
    /// Reads an immutable scan page, retaining a bounded snapshot on first use.
    ///
    /// The caller rechecks current IAM and resource authority independently.
    /// One SQL statement captures all admitted summaries; later pages never
    /// consult changing scan state. Snapshots expire after fifteen minutes.
    ///
    /// # Errors
    /// Returns an error for invalid selectors, expired or foreign cursors,
    /// excessive row/storage bounds, corrupt retained content or SQL failure.
    pub async fn assessment_retained_scan_page(
        &self,
        registry_id: i64,
        resource_scope: &str,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ScanListV1> {
        if !(1..=100).contains(&limit) {
            bail!("invalid retained scan page size");
        }
        if self
            .registry_by_id(registry_id)
            .await?
            .is_none_or(|registry| registry.scope_key != resource_scope)
        {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if let Some(cursor) = cursor {
            let (digest, handle) = parse_scan_cursor(cursor)?;
            let bytes = self
                .assessment_object(
                    resource_scope,
                    AssessmentObjectKind::ScanReadSnapshot,
                    digest,
                )
                .await?
                .ok_or(ScanPageError::CursorExpired)?;
            let snapshot = ScanReadSnapshotV1::from_slice(&bytes)?;
            return snapshot.page(
                resource_scope,
                limit,
                Some(handle),
                &self.assessment_database_time().await?,
            );
        }

        let rows = self
            .assessment_scan_summary_rows(registry_id, "", 10_001)
            .await?;
        if rows.len() > 10_000 {
            return Err(ScanPageError::CapacityExceeded.into());
        }
        let as_of = self.assessment_database_time().await?;
        let snapshot = ScanReadSnapshotV1 {
            schema: SCAN_READ_SNAPSHOT_V1.into(),
            resource_scope: resource_scope.into(),
            limit,
            expires_at: Timestamp::from_unix_seconds(
                as_of
                    .unix_seconds()
                    .checked_add(900)
                    .context("scan snapshot deadline overflow")?,
            )?,
            as_of,
            page_handles: (1..rows.len().div_ceil(limit as usize))
                .map(|_| uuid::Uuid::new_v4().simple().to_string())
                .collect(),
            scans: rows
                .into_iter()
                .map(|row| ScanSummary {
                    scan_id: row.scan_id,
                    request_digest: row.request_digest,
                    state: row.state,
                    generation: row.generation,
                    resource_version: row.resource_version,
                    created_at: row.created_at,
                    assessment_digest: row.assessment_digest,
                })
                .collect(),
        };
        let page = snapshot.page(resource_scope, limit, None, &snapshot.as_of)?;
        if !snapshot.page_handles.is_empty() {
            if let Err(error) = self
                .put_assessment_object(
                    resource_scope,
                    AssessmentObjectKind::ScanReadSnapshot,
                    snapshot.digest()?,
                    &snapshot.to_bytes()?,
                    i64::try_from(snapshot.as_of.unix_seconds())?,
                )
                .await
            {
                let count = self.backend.query_opt(
                    "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
                    &vals![@slice resource_scope, SCAN_READ_SNAPSHOT_V1],
                ).await?.context("scan snapshot count is absent")?.get::<u64>(0)?;
                if count >= 16 {
                    return Err(ScanPageError::CapacityExceeded.into());
                }
                return Err(error);
            }
        }
        Ok(page)
    }
}
