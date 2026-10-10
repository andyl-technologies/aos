//! Immutable advisory captures with bounded index and object-custody reads.
//!
//! Live history captures its complete finite identity vector in one SQL query.
//! Historical assessment reads use the existing frozen semantic closure. Neither
//! path acquires providers, selects a new head or grants source authority.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::advisory::AdvisoryRecordV1;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::advisories::retained::{
    parse_advisory_cursor, AdvisoryPageV2, AdvisoryQueryV2, AdvisoryReadSnapshotV1,
    ADVISORY_READ_SNAPSHOT_V1,
};
use aos_assessment_runtime::advisories::{AdvisoryPageV1, AdvisoryRevisionV1};
use aos_assessment_runtime::read_snapshot::ScanPageError;
use aos_contract::Sha256Digest;

use super::AssessmentObjectKind;
use crate::db::Database;

impl Database {
    /// Reads retained exact advisory pages under an original finite selection.
    ///
    /// Current registry and read authority are independently checked by the
    /// service before and after the read. Continuations preserve original
    /// revisions, withdrawal facts, finding links and observation time.
    ///
    /// # Errors
    /// Returns an error for changed selectors, expired or forged cursors,
    /// exceeded revision/storage bounds, missing custody or database failure.
    pub async fn assessment_retained_advisory_page(
        &self,
        registry_id: i64,
        query: &AdvisoryQueryV2,
    ) -> Result<Option<AdvisoryPageV2>> {
        query.validate()?;
        let Some(registry) = self.registry_by_id(registry_id).await? else {
            return Ok(None);
        };
        if query
            .resource_scope
            .as_ref()
            .is_some_and(|scope| scope != &registry.scope_key)
        {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if let Some(cursor) = &query.cursor {
            let (digest, _) = parse_advisory_cursor(cursor)?;
            let bytes = self
                .assessment_object(
                    &registry.scope_key,
                    AssessmentObjectKind::AdvisoryReadSnapshot,
                    digest,
                )
                .await?
                .ok_or(ScanPageError::CursorExpired)?;
            let snapshot = AdvisoryReadSnapshotV1::from_slice(&bytes)?;
            return snapshot
                .page(query, &self.assessment_database_time().await?)
                .map(Some);
        }

        let mut legacy = query.legacy_selection();
        legacy.resource_scope = Some(registry.scope_key.clone());
        legacy.limit = 10;
        let mut base;
        let revisions;
        if query.assessment_digest.is_some() {
            let Some(first) = self.assessment_advisory_page(registry_id, &legacy).await? else {
                return Ok(None);
            };
            first.validate_for(&legacy)?;
            base = first.clone();
            let mut collected = first.revisions;
            let mut cursor = first.next_record;
            // The assessment and its frozen snapshot are immutable. Each finite
            // projection binds the same assessment/subject and cannot add live
            // provider revisions. Bound the whole capture, not only each page.
            while let Some(after) = cursor {
                legacy.after_record = Some(after);
                let page = self
                    .assessment_advisory_page(registry_id, &legacy)
                    .await?
                    .context("historical advisory custody changed")?;
                ensure!(
                    page.assessment_context == base.assessment_context,
                    "advisory capture historical context changed"
                );
                page.validate_for(&legacy)?;
                collected.extend(page.revisions);
                if collected.len() > 128 {
                    return Err(ScanPageError::CapacityExceeded.into());
                }
                cursor = page.next_record;
            }
            revisions = collected;
        } else {
            revisions = self
                .assessment_advisory_capture_records(&registry.scope_key, &query.advisory_id)
                .await?;
            base = AdvisoryPageV1 {
                schema: "aos.assessment-advisory-page/v1".into(),
                resource_scope: registry.scope_key.clone(),
                advisory_id: query.advisory_id.clone(),
                as_of: self.assessment_database_time().await?,
                assessment_context: None,
                revisions: vec![],
                next_record: None,
            };
        }
        base.revisions.clear();
        base.next_record = None;
        let pages = if revisions.is_empty() {
            vec![base.clone()]
        } else {
            revisions
                .chunks(query.limit as usize)
                .map(|revisions| {
                    let mut page = base.clone();
                    page.revisions = revisions.to_vec();
                    page
                })
                .collect::<Vec<_>>()
        };
        let mut selection = query.clone();
        selection.resource_scope = Some(registry.scope_key.clone());
        let snapshot = AdvisoryReadSnapshotV1 {
            schema: ADVISORY_READ_SNAPSHOT_V1.into(),
            selection,
            expires_at: Timestamp::from_unix_seconds(
                base.as_of
                    .unix_seconds()
                    .checked_add(900)
                    .context("advisory capture deadline overflow")?,
            )?,
            page_handles: (1..pages.len())
                .map(|_| uuid::Uuid::new_v4().simple().to_string())
                .collect(),
            pages,
        };
        let page = snapshot.page(query, &base.as_of)?;
        if !snapshot.page_handles.is_empty() {
            if let Err(error) = self
                .put_assessment_object(
                    &registry.scope_key,
                    AssessmentObjectKind::AdvisoryReadSnapshot,
                    snapshot.digest()?,
                    &snapshot.to_bytes()?,
                    i64::try_from(base.as_of.unix_seconds())?,
                )
                .await
            {
                let count: u64 = self.backend.query_opt(
                    "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
                    &vals![@slice registry.scope_key, ADVISORY_READ_SNAPSHOT_V1],
                ).await?.context("advisory capture count")?.get(0)?;
                if count >= 16 {
                    return Err(ScanPageError::CapacityExceeded.into());
                }
                return Err(error);
            }
        }
        Ok(Some(page))
    }

    async fn assessment_advisory_capture_records(
        &self,
        partition: &str,
        advisory_id: &str,
    ) -> Result<Vec<AdvisoryRevisionV1>> {
        let identity = Sha256Digest::of_canonical("aos.advisory-identity/v1", &advisory_id)?;
        // One consistent, small identity-vector read precedes every blob read.
        // LEFT JOIN makes missing custody explicit rather than silently omitting
        // a revision. Excess rows/bytes fail before objects cross the backend.
        let rows = self.backend.query(
            "SELECT identity.record_digest, object.byte_length
             FROM assessment_advisory_identity_index identity
             LEFT JOIN assessment_objects object ON object.partition_key = identity.partition_key
                 AND object.object_digest = identity.record_digest AND object.object_kind = ?3
             WHERE identity.partition_key = ?1 AND identity.identity_digest = ?2
             ORDER BY identity.record_digest LIMIT 129",
            &vals![@slice partition, identity.to_string(), AssessmentObjectKind::AdvisoryRecord.domain()],
        ).await?;
        if rows.len() > 128 {
            return Err(ScanPageError::CapacityExceeded.into());
        }
        let mut bytes = 0u64;
        for row in &rows {
            let length = row
                .get::<Option<u64>>(1)?
                .context("indexed advisory custody is absent")?;
            bytes = bytes
                .checked_add(length)
                .context("advisory capture byte count overflow")?;
            if bytes > 8 * 1024 * 1024 {
                return Err(ScanPageError::CapacityExceeded.into());
            }
        }
        let mut revisions = Vec::with_capacity(rows.len());
        for row in rows {
            let digest = Sha256Digest::parse(&row.get::<String>(0)?)?;
            let bytes = self
                .assessment_object(partition, AssessmentObjectKind::AdvisoryRecord, digest)
                .await?
                .context("captured advisory custody is absent")?;
            let record = AdvisoryRecordV1::from_slice(&bytes)?;
            ensure!(
                record.digest()? == digest
                    && (record.id == advisory_id
                        || record.aliases.iter().any(|alias| alias == advisory_id)),
                "captured advisory equivalence changed"
            );
            revisions.push(AdvisoryRevisionV1 {
                record_digest: digest,
                record,
                finding_links: vec![],
            });
        }
        Ok(revisions)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "advisory_snapshot_tests.rs"]
pub(super) mod tests;
