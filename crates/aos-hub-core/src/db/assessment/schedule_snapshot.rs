//! Retained schedule reviews on Native SQL and Worker HubDb.
//!
//! Original public revisions and due times survive review replacement, schedule
//! advancement and database reopen. Current caller authority remains independent.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::read_snapshot::{
    schedules::{parse_schedule_cursor, ScheduleReadSnapshotV1, SCHEDULE_READ_SNAPSHOT_V1},
    ScanPageError,
};
use aos_assessment_runtime::schedules::SchedulePageV1;

use super::AssessmentObjectKind;
use crate::db::Database;

impl Database {
    /// Captures or continues a bounded immutable public schedule listing.
    ///
    /// Reads never renew reviews, advance due times or admit scans. Hosts
    /// independently authorize every page against the current resource.
    ///
    /// # Errors
    /// Returns an error for invalid selectors, expired or forged cursors,
    /// exhausted capacity, corrupt custody or unavailable persistence.
    pub async fn assessment_retained_schedule_page(
        &self,
        registry_id: i64,
        scope: &str,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<SchedulePageV1> {
        ensure!(
            (1..=10).contains(&limit),
            "invalid schedule capture page size"
        );
        if self
            .registry_by_id(registry_id)
            .await?
            .is_none_or(|registry| registry.scope_key != scope)
        {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if let Some(cursor) = cursor {
            let (digest, handle) = parse_schedule_cursor(cursor)?;
            let bytes = self
                .assessment_object(scope, AssessmentObjectKind::ScheduleReadSnapshot, digest)
                .await?
                .ok_or(ScanPageError::CursorExpired)?;
            let snapshot = ScheduleReadSnapshotV1::from_slice(&bytes)?;
            return snapshot.page(
                scope,
                limit,
                Some(handle),
                &self.assessment_database_time().await?,
            );
        }

        let schedules = self.assessment_schedule_capture(registry_id, scope).await?;
        let as_of = self.assessment_database_time().await?;
        let snapshot = ScheduleReadSnapshotV1 {
            schema: SCHEDULE_READ_SNAPSHOT_V1.into(),
            resource_scope: scope.into(),
            limit,
            expires_at: Timestamp::from_unix_seconds(
                as_of
                    .unix_seconds()
                    .checked_add(900)
                    .context("schedule capture deadline overflow")?,
            )?,
            as_of,
            page_handles: (1..schedules.len().div_ceil(limit as usize))
                .map(|_| uuid::Uuid::new_v4().simple().to_string())
                .collect(),
            schedules,
        };
        let page = snapshot.page(scope, limit, None, &snapshot.as_of)?;
        if !snapshot.page_handles.is_empty() {
            let bytes = snapshot
                .to_bytes()
                .map_err(|_| ScanPageError::CapacityExceeded)?;
            if let Err(error) = self
                .put_assessment_object(
                    scope,
                    AssessmentObjectKind::ScheduleReadSnapshot,
                    snapshot.digest()?,
                    &bytes,
                    i64::try_from(snapshot.as_of.unix_seconds())?,
                )
                .await
            {
                let count = self.backend.query_opt(
                    "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
                    &vals![@slice scope, SCHEDULE_READ_SNAPSHOT_V1],
                ).await?.context("schedule capture count is absent")?.get::<u64>(0)?;
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
#[path = "schedule_snapshot_tests.rs"]
pub(super) mod tests;
