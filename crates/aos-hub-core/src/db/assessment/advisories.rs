//! Exact registry-scoped advisory reads from admitted provider or assessment custody.
//!
//! Reads never acquire evidence or update provider heads. An explicit assessment
//! selection uses its frozen evaluation closure, including records that have no
//! live provider index. Historical scope is distinct from current package status.

use anyhow::{Context as _, Result};
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::advisories::{AdvisoryPageV1, AdvisoryQueryV1, AdvisoryRevisionV1};

use crate::db::Database;

use super::AssessmentObjectKind;

impl Database {
    /// Reads a finite exact advisory page within the selected registry incarnation.
    ///
    /// A selected assessment must have a successful scoped admission and a retained
    /// frozen advisory snapshot. `None` denotes an unavailable resource or historical
    /// selection, never negative vulnerability evidence. The caller checks current IAM
    /// before and after this read and enforces the response byte budget.
    ///
    /// # Errors
    /// Returns an error for invalid selection, conflicting custody or persistence failure.
    pub async fn assessment_advisory_page(
        &self,
        registry_id: i64,
        query: &AdvisoryQueryV1,
    ) -> Result<Option<AdvisoryPageV1>> {
        query.validate()?;
        let Some(registry) = self.registry_by_id(registry_id).await? else {
            return Ok(None);
        };
        if query
            .resource_scope
            .as_ref()
            .is_some_and(|scope| scope != &registry.scope_key)
        {
            return Ok(None);
        }
        let mut records = if let Some(digest) = query.assessment_digest {
            let Some(row) = self.backend.query_opt(
                "SELECT scan_id FROM assessment_scans WHERE registry_id = ?1 AND admission_complete = 1
                 AND state IN ('succeeded', 'partial') AND assessment_digest = ?2 ORDER BY scan_id LIMIT 1",
                &vals![@slice registry_id, digest.to_string()],
            ).await? else {
                return Ok(None);
            };
            let scan_id = row.get::<String>(0)?;
            let (input, data) = self
                .assessment_frozen_evaluation(registry_id, &scan_id)
                .await?;
            if data.advisory_snapshot.is_none() {
                return Ok(None);
            }
            let bytes = self
                .assessment_object(
                    &registry.scope_key,
                    AssessmentObjectKind::Assessment,
                    digest,
                )
                .await?
                .context("admitted assessment custody is absent")?;
            let selected = PackageAssessmentV1::from_slice(&bytes)?;
            if query.subject_ref.as_ref().is_some_and(|subject| {
                !selected
                    .subject_results
                    .iter()
                    .any(|result| &result.subject_ref == subject)
            }) {
                return Ok(None);
            }
            return aos_assessment_runtime::advisories::lookup_assessment(
                query,
                &input,
                &data,
                &selected,
                registry.scope_key,
                self.assessment_database_time().await?,
            )
            .map(Some);
        } else {
            self.assessment_advisory_revision_page(
                &registry.scope_key,
                &query.advisory_id,
                &query
                    .after_record
                    .map(|digest| digest.to_string())
                    .unwrap_or_default(),
                query.limit + 1,
            )
            .await?
        };
        let has_more = records.len() > query.limit as usize;
        records.truncate(query.limit as usize);
        let revisions = records
            .into_iter()
            .map(|record| {
                let digest = record.digest()?;
                Ok(AdvisoryRevisionV1 {
                    record_digest: digest,
                    record,
                    finding_links: vec![],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next_record = has_more
            .then(|| revisions.last().map(|revision| revision.record_digest))
            .flatten();
        Ok(Some(AdvisoryPageV1 {
            schema: "aos.assessment-advisory-page/v1".into(),
            resource_scope: registry.scope_key,
            advisory_id: query.advisory_id.clone(),
            as_of: self.assessment_database_time().await?,
            assessment_context: None,
            revisions,
            next_record,
        }))
    }
}
