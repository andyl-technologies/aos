//! Shared historical advisory projection over one already admitted evaluation closure.

use anyhow::{Result, ensure};
use aos_assessment::input::{EvaluationData, ScanInputV1};
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment::time::Timestamp;

use super::{
    AdvisoryAssessmentContext, AdvisoryFindingLink, AdvisoryPageV1, AdvisoryProjectionLimit,
    AdvisoryQueryV1, AdvisoryRevisionV1,
};

/// Projects exact snapshot revisions and raw finding links without source acquisition.
///
/// The caller separately establishes admission and current read authority. This
/// projection verifies immutable input/closure/result bindings; it neither admits
/// imported evidence nor advances any current head. Native, Worker and local
/// adapters use the same selection and response validation.
///
/// # Errors
/// Returns an error for inconsistent closure/result identity, missing advisory
/// snapshot, absent selected subject or excessive response size/link count.
pub fn lookup_assessment(
    query: &AdvisoryQueryV1,
    input: &ScanInputV1,
    data: &EvaluationData,
    assessment: &PackageAssessmentV1,
    resource_scope: String,
    as_of: Timestamp,
) -> Result<AdvisoryPageV1> {
    query.validate()?;
    ensure!(
        query.assessment_digest == Some(assessment.digest()?)
            && assessment.input_digest == input.digest()?,
        "advisory selection differs from its exact assessment input"
    );
    ensure!(
        data.freeze_selected(
            input.profiles.clone(),
            input.subject_refs.clone(),
            input.evaluated_at.clone()
        )? == *input,
        "advisory closure differs from its frozen input"
    );
    let snapshot = data
        .advisory_snapshot
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("selected assessment has no advisory snapshot"))?;
    let snapshot_digest = snapshot.digest()?;
    ensure!(
        input.advisory_snapshot_digest == Some(snapshot_digest),
        "advisory snapshot differs from its frozen input"
    );
    ensure!(
        query.subject_ref.as_ref().is_none_or(|subject| assessment
            .subject_results
            .iter()
            .any(|result| &result.subject_ref == subject)),
        "selected advisory subject is absent from its assessment"
    );

    let mut records = data
        .advisories
        .iter()
        .filter(|record| {
            record.id == query.advisory_id
                || record
                    .aliases
                    .iter()
                    .any(|alias| alias == &query.advisory_id)
        })
        .map(|record| Ok((record.digest()?, record)))
        .collect::<Result<Vec<_>>>()?;
    records.sort_by_key(|(digest, _)| *digest);
    let records = records
        .into_iter()
        .filter(|(digest, _)| query.after_record.is_none_or(|after| *digest > after))
        .take(query.limit as usize + 1)
        .collect::<Vec<_>>();
    let has_more = records.len() > query.limit as usize;
    let mut revisions = Vec::new();
    for (digest, record) in records.into_iter().take(query.limit as usize) {
        let mut finding_links = Vec::new();
        for subject in &assessment.subject_results {
            if query
                .subject_ref
                .as_ref()
                .is_some_and(|selected| selected != &subject.subject_ref)
            {
                continue;
            }
            for finding in &subject.findings {
                if finding
                    .advisory_record_digests
                    .binary_search(&digest)
                    .is_ok()
                {
                    if finding_links.len() == 100 {
                        return Err(AdvisoryProjectionLimit::FindingLinks.into());
                    }
                    finding_links.push(AdvisoryFindingLink {
                        subject_ref: subject.subject_ref.clone(),
                        component_ref: finding.component_ref.clone(),
                        finding_key: finding.finding_key,
                        applicability: finding.applicability,
                    });
                }
            }
        }
        revisions.push(AdvisoryRevisionV1 {
            record_digest: digest,
            record: record.clone(),
            finding_links,
        });
    }
    let next_record = if has_more {
        revisions.last().map(|revision| revision.record_digest)
    } else {
        None
    };
    let page = AdvisoryPageV1 {
        schema: "aos.assessment-advisory-page/v1".into(),
        resource_scope,
        advisory_id: query.advisory_id.clone(),
        as_of,
        assessment_context: Some(AdvisoryAssessmentContext {
            assessment_digest: assessment.digest()?,
            input_digest: assessment.input_digest,
            snapshot_digest,
            policy_digest: input.policy_digest,
            evaluated_at: input.evaluated_at.clone(),
            subject_ref: query.subject_ref.clone(),
        }),
        revisions,
        next_record,
    };
    page.validate_for(query)?;
    Ok(page)
}
