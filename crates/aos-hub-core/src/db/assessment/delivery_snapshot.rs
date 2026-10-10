//! Retained notification deliveries on Native SQL and Worker HubDb.
//!
//! Original states, attempt counters, receipts and batch commitments survive
//! physical retry and database reopen. Current read authority remains independent.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::notifications::NotificationDeliveryPageV1;
use aos_assessment_runtime::read_snapshot::{
    deliveries::{parse_delivery_cursor, DeliveryReadSnapshotV1, DELIVERY_READ_SNAPSHOT_V1},
    ScanPageError,
};

use super::AssessmentObjectKind;
use crate::db::Database;

impl Database {
    /// Captures or continues a bounded immutable public delivery listing.
    ///
    /// Reads never claim, retry or dispatch notification intents. Hosts
    /// independently authorize every page against the current resource.
    ///
    /// # Errors
    /// Returns an error for invalid selectors, expired or forged cursors,
    /// exhausted capacity, corrupt custody or unavailable persistence.
    pub async fn assessment_retained_delivery_page(
        &self,
        registry_id: i64,
        scope: &str,
        limit: u32,
        subscription_id: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<NotificationDeliveryPageV1> {
        ensure!(
            (1..=10).contains(&limit),
            "invalid delivery capture page size"
        );
        if let Some(identity) = subscription_id {
            ensure!(
                !identity.is_empty()
                    && identity.len() <= 128
                    && !identity.chars().any(char::is_control),
                "invalid delivery capture subscription"
            );
        }
        if self
            .registry_by_id(registry_id)
            .await?
            .is_none_or(|registry| registry.scope_key != scope)
        {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if let Some(cursor) = cursor {
            let (digest, handle) = parse_delivery_cursor(cursor)?;
            let bytes = self
                .assessment_object(scope, AssessmentObjectKind::DeliveryReadSnapshot, digest)
                .await?
                .ok_or(ScanPageError::CursorExpired)?;
            let snapshot = DeliveryReadSnapshotV1::from_slice(&bytes)?;
            return snapshot.page(
                scope,
                limit,
                subscription_id,
                Some(handle),
                &self.assessment_database_time().await?,
            );
        }

        let deliveries = self
            .assessment_delivery_capture(registry_id, subscription_id)
            .await?;
        let as_of = self.assessment_database_time().await?;
        let snapshot = DeliveryReadSnapshotV1 {
            schema: DELIVERY_READ_SNAPSHOT_V1.into(),
            resource_scope: scope.into(),
            subscription_id: subscription_id.map(str::to_owned),
            limit,
            expires_at: Timestamp::from_unix_seconds(
                as_of
                    .unix_seconds()
                    .checked_add(900)
                    .context("delivery capture deadline overflow")?,
            )?,
            as_of,
            page_handles: (1..deliveries.len().div_ceil(limit as usize))
                .map(|_| uuid::Uuid::new_v4().simple().to_string())
                .collect(),
            deliveries,
        };
        let page = snapshot.page(scope, limit, subscription_id, None, &snapshot.as_of)?;
        if !snapshot.page_handles.is_empty() {
            let bytes = snapshot
                .to_bytes()
                .map_err(|_| ScanPageError::CapacityExceeded)?;
            if let Err(error) = self
                .put_assessment_object(
                    scope,
                    AssessmentObjectKind::DeliveryReadSnapshot,
                    snapshot.digest()?,
                    &bytes,
                    i64::try_from(snapshot.as_of.unix_seconds())?,
                )
                .await
            {
                let count = self.backend.query_opt(
                    "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
                    &vals![@slice scope, DELIVERY_READ_SNAPSHOT_V1],
                ).await?.context("delivery capture count is absent")?.get::<u64>(0)?;
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
#[path = "delivery_snapshot_tests.rs"]
pub(super) mod tests;
