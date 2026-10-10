//! Bounded immutable attention captures shared by Native SQL and Worker HubDb.
//!
//! A single ordered query observes original alert revisions. Retained pages do
//! not re-read heads and cannot acknowledge, resolve or reopen an episode.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::attention_control::AlertPageV1;
use aos_assessment_runtime::read_snapshot::{
    alerts::{parse_alert_cursor, AlertReadSnapshotV1, ALERT_READ_SNAPSHOT_V1, MAX_CAPTURE_ALERTS},
    ScanPageError,
};

use super::AssessmentObjectKind;
use crate::db::Database;

// Leave room for the envelope and page handles inside the eight MiB contract.
const MAX_CAPTURE_RAW_BYTES: u64 = 8 * 1024 * 1024 - 16 * 1024;

impl Database {
    /// Captures or continues an immutable listing of original attention episodes.
    ///
    /// Current caller authority is checked separately by the service. The read
    /// makes no provider requests and confers no acknowledgement authority.
    ///
    /// # Errors
    /// Returns an error for replaced resources, invalid or expired cursors,
    /// exhausted record/storage bounds, corrupt custody or persistence failure.
    pub async fn assessment_retained_alert_page(
        &self,
        registry_id: i64,
        scope: &str,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<AlertPageV1> {
        ensure!((1..=10).contains(&limit), "invalid alert capture page size");
        if self
            .registry_by_id(registry_id)
            .await?
            .is_none_or(|registry| registry.scope_key != scope)
        {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if let Some(cursor) = cursor {
            let (digest, handle) = parse_alert_cursor(cursor)?;
            let bytes = self
                .assessment_object(scope, AssessmentObjectKind::AlertReadSnapshot, digest)
                .await?
                .ok_or(ScanPageError::CursorExpired)?;
            return AlertReadSnapshotV1::from_slice(&bytes)?.page(
                scope,
                limit,
                Some(handle),
                &self.assessment_database_time().await?,
            );
        }

        // The metadata row and original revisions share one SQL observation.
        // Oversized captures return only their bounds, avoiding a large HubDb
        // response or Worker allocation before the caller can reject it.
        let rows = self
            .backend
            .query(
                "WITH attention_capture AS (
                SELECT issue_key, alert_json FROM assessment_alerts WHERE registry_id = ?1
             ), capture_bounds AS (
                SELECT COUNT(*) AS record_count, COALESCE(SUM(LENGTH(alert_json)), 0) AS byte_count
                FROM attention_capture
             )
             SELECT NULL AS alert_json, '' AS issue_key, record_count, byte_count, 0 AS row_kind
             FROM capture_bounds
             UNION ALL
             SELECT a.alert_json, a.issue_key, b.record_count, b.byte_count, 1 AS row_kind
             FROM attention_capture a CROSS JOIN capture_bounds b
             WHERE b.record_count <= ?2 AND b.byte_count <= ?3
             ORDER BY row_kind, issue_key",
                &vals![@slice registry_id, MAX_CAPTURE_ALERTS as u32, MAX_CAPTURE_RAW_BYTES],
            )
            .await?;
        let bounds = rows.first().context("alert capture bounds are absent")?;
        let record_count = bounds.get::<u64>(2)?;
        if record_count > MAX_CAPTURE_ALERTS as u64 || bounds.get::<u64>(3)? > MAX_CAPTURE_RAW_BYTES
        {
            return Err(ScanPageError::CapacityExceeded.into());
        }
        ensure!(
            bounds.get::<u64>(4)? == 0 && rows.len() as u64 == record_count + 1,
            "alert capture differs from its atomic bounds"
        );
        let alerts = rows
            .iter()
            .skip(1)
            .map(|row| {
                let bytes = row.get::<Vec<u8>>(0)?;
                super::alerts::decode_alert(&bytes)
            })
            .collect::<Result<Vec<_>>>()?;
        let as_of = self.assessment_database_time().await?;
        let snapshot = AlertReadSnapshotV1 {
            schema: ALERT_READ_SNAPSHOT_V1.into(),
            resource_scope: scope.into(),
            limit,
            expires_at: Timestamp::from_unix_seconds(
                as_of
                    .unix_seconds()
                    .checked_add(900)
                    .context("alert capture deadline overflow")?,
            )?,
            as_of,
            page_handles: (1..alerts.len().div_ceil(limit as usize))
                .map(|_| uuid::Uuid::new_v4().simple().to_string())
                .collect(),
            alerts,
        };
        let page = snapshot.page(scope, limit, None, &snapshot.as_of)?;
        if !snapshot.page_handles.is_empty() {
            let bytes = snapshot
                .to_bytes()
                .map_err(|_| ScanPageError::CapacityExceeded)?;
            if let Err(error) = self
                .put_assessment_object(
                    scope,
                    AssessmentObjectKind::AlertReadSnapshot,
                    snapshot.digest()?,
                    &bytes,
                    i64::try_from(snapshot.as_of.unix_seconds())?,
                )
                .await
            {
                let count = self.backend.query_opt(
                    "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
                    &vals![@slice scope, ALERT_READ_SNAPSHOT_V1],
                ).await?.context("alert capture count is absent")?.get::<u64>(0)?;
                if count >= 16 {
                    return Err(ScanPageError::CapacityExceeded.into());
                }
                return Err(error);
            }
        }
        Ok(page)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "alert_snapshot_tests.rs"]
pub(super) mod tests;
