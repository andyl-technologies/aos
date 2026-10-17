//! Retained public subscription captures on Native SQL and Worker HubDb.
//!
//! A single review-row query supplies each initial capture. Stored captures
//! contain public commitments only; current IAM is enforced independently.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::notifications::SubscriptionPageV1;
use aos_assessment_runtime::read_snapshot::{
    subscriptions::{
        parse_subscription_cursor, SubscriptionReadSnapshotV1, SUBSCRIPTION_READ_SNAPSHOT_V1,
    },
    ScanPageError,
};

use super::AssessmentObjectKind;
use crate::db::Database;

impl Database {
    /// Captures or continues an immutable, finite public subscription listing.
    ///
    /// Reads never renew reviews, dispatch callbacks or acquire source evidence.
    /// Every continuation requires separate current caller authorization.
    ///
    /// # Errors
    /// Returns an error for changed selectors, invalid or expired cursors,
    /// exhausted retained capacity, corrupt custody or unavailable persistence.
    pub async fn assessment_retained_subscription_page(
        &self,
        registry_id: i64,
        scope: &str,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<SubscriptionPageV1> {
        ensure!(
            (1..=10).contains(&limit),
            "invalid subscription capture page size"
        );
        if self
            .registry_by_id(registry_id)
            .await?
            .is_none_or(|registry| registry.scope_key != scope)
        {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if let Some(cursor) = cursor {
            let (digest, handle) = parse_subscription_cursor(cursor)?;
            let bytes = self
                .assessment_object(
                    scope,
                    AssessmentObjectKind::SubscriptionReadSnapshot,
                    digest,
                )
                .await?
                .ok_or(ScanPageError::CursorExpired)?;
            let snapshot = SubscriptionReadSnapshotV1::from_slice(&bytes)?;
            return snapshot.page(
                scope,
                limit,
                Some(handle),
                &self.assessment_database_time().await?,
            );
        }

        let records = self.subscription_records(registry_id).await?;
        let mut subscriptions = records
            .iter()
            .map(|record| super::notifications::project(scope, record))
            .collect::<Result<Vec<_>>>()?;
        subscriptions.sort_by(|left, right| left.subscription_id.cmp(&right.subscription_id));
        let as_of = self.assessment_database_time().await?;
        let snapshot = SubscriptionReadSnapshotV1 {
            schema: SUBSCRIPTION_READ_SNAPSHOT_V1.into(),
            resource_scope: scope.into(),
            limit,
            expires_at: Timestamp::from_unix_seconds(
                as_of
                    .unix_seconds()
                    .checked_add(900)
                    .context("subscription snapshot deadline overflow")?,
            )?,
            as_of,
            page_handles: (1..subscriptions.len().div_ceil(limit as usize))
                .map(|_| uuid::Uuid::new_v4().simple().to_string())
                .collect(),
            subscriptions,
        };
        let page = snapshot.page(scope, limit, None, &snapshot.as_of)?;
        if !snapshot.page_handles.is_empty() {
            if let Err(error) = self
                .put_assessment_object(
                    scope,
                    AssessmentObjectKind::SubscriptionReadSnapshot,
                    snapshot.digest()?,
                    &snapshot.to_bytes()?,
                    i64::try_from(snapshot.as_of.unix_seconds())?,
                )
                .await
            {
                let count = self.backend.query_opt(
                    "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
                    &vals![@slice scope, SUBSCRIPTION_READ_SNAPSHOT_V1],
                ).await?.context("subscription snapshot count is absent")?.get::<u64>(0)?;
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
#[path = "subscription_snapshot_tests.rs"]
pub(super) mod tests;
