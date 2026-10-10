//! Resource-scoped advisory revision lookup without provider effects.
//!
//! A selected admitted assessment pins its advisory snapshot and finding links.
//! Otherwise the lookup returns retained historical revisions. Neither a cache
//! miss nor an empty association set establishes fresh negative coverage.
//!
//! ```json
//! {"schema":"aos.assessment-advisory-query/v1","advisoryId":"CVE-2026-12345","limit":10}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::advisory::{AdvisoryRecordV1, is_cve_id};
use aos_assessment::result::Applicability;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::validation::{decode, encoded, text};

mod assessment;

pub use assessment::lookup_assessment;

/// Selects exact cached advisory equivalence and an optional admitted assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryQueryV1 {
    /// Exact query discriminator.
    pub schema: String,
    /// Exact provider-native identifier or canonical CVE identifier.
    pub advisory_id: String,
    /// Registry incarnation, required on continuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
    /// Successfully admitted assessment whose immutable snapshot limits revisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_digest: Option<Sha256Digest>,
    /// Optional subject selection within that exact admitted assessment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    /// Exclusive examined record identity from the preceding page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_record: Option<Sha256Digest>,
    /// Maximum matching revisions returned, from one through ten.
    pub limit: u32,
}

impl AdvisoryQueryV1 {
    /// Decodes a closed query before database reads or credential selection.
    ///
    /// # Errors
    /// Returns an error for unknown fields, malformed identities or invalid selection.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let query: Self = decode(bytes, "advisory query")?;
        query.validate()?;
        Ok(query)
    }

    /// Checks exact identifiers, finite work and incarnation-bound continuation.
    ///
    /// # Errors
    /// Returns an error for invalid schema, CVE grammar, bounds or ambiguous scope.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-advisory-query/v1" && (1..=10).contains(&self.limit),
            "invalid advisory query"
        );
        text(&self.advisory_id, 128, "advisory identifier")?;
        ensure!(
            !self.advisory_id.starts_with("CVE-") || is_cve_id(&self.advisory_id),
            "invalid canonical CVE identifier"
        );
        for value in [&self.resource_scope, &self.subject_ref]
            .into_iter()
            .flatten()
        {
            text(value, 128, "advisory selection")?;
        }
        ensure!(
            self.after_record.is_none() || self.resource_scope.is_some(),
            "advisory continuation requires its original registry incarnation"
        );
        ensure!(
            self.subject_ref.is_none() || self.assessment_digest.is_some(),
            "advisory subject selection requires an admitted assessment"
        );
        Ok(())
    }
}

/// Links a revision to a raw finding in the explicitly selected assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryFindingLink {
    /// Portable subject identity within the selected assessment.
    pub subject_ref: String,
    /// Portable component identity within that subject.
    pub component_ref: String,
    /// Stable finding identity; acknowledgement and dispositions remain separate.
    pub finding_key: Sha256Digest,
    /// Original match conclusion at the assessment's evaluation time.
    pub applicability: Applicability,
}

/// Retains a complete normalized revision and explicit finding links.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryRevisionV1 {
    /// Exact canonical normalized record commitment.
    pub record_digest: Sha256Digest,
    /// Original bounded source claims, including severity, ranges and withdrawal.
    pub record: AdvisoryRecordV1,
    /// At most one hundred sorted subject/finding links in the selected assessment.
    pub finding_links: Vec<AdvisoryFindingLink>,
}

/// Identifies the immutable historical context used for private finding links.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryAssessmentContext {
    /// Successfully admitted assessment; this response does not assert currentness.
    pub assessment_digest: Sha256Digest,
    /// Exact frozen semantic input used to evaluate that assessment.
    pub input_digest: Sha256Digest,
    /// Exact admitted advisory snapshot used by that input.
    pub snapshot_digest: Sha256Digest,
    /// Immutable policy used for matching and source freshness at evaluation.
    pub policy_digest: Sha256Digest,
    /// Original explicit evaluation time, separate from the response observation time.
    pub evaluated_at: Timestamp,
    /// Applied optional subject selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
}

/// Returns retained revisions without inferring affected, clean or latest status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryPageV1 {
    /// Exact response discriminator.
    pub schema: String,
    /// Exact authorized registry incarnation.
    pub resource_scope: String,
    /// Exact original advisory identifier.
    pub advisory_id: String,
    /// Database time of this read, which never refreshes source evidence.
    pub as_of: Timestamp,
    /// Optional historical assessment and snapshot binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_context: Option<AdvisoryAssessmentContext>,
    /// At most ten matching revisions in canonical record identity order.
    pub revisions: Vec<AdvisoryRevisionV1>,
    /// Last returned record identity when more matching revisions remain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_record: Option<Sha256Digest>,
}

impl AdvisoryPageV1 {
    /// Checks commitments, equivalence, finding links and finite response size.
    ///
    /// # Errors
    /// Returns an error for invalid schema, scope, revisions, links or response bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-advisory-page/v1" && self.revisions.len() <= 10,
            "invalid advisory page"
        );
        text(&self.resource_scope, 128, "advisory page resource")?;
        text(&self.advisory_id, 128, "advisory page identifier")?;
        ensure!(
            !self.advisory_id.starts_with("CVE-") || is_cve_id(&self.advisory_id),
            "invalid canonical CVE page identifier"
        );
        if let Some(context) = &self.assessment_context
            && let Some(subject) = &context.subject_ref
        {
            text(subject, 128, "advisory context subject")?;
        }
        ensure!(
            self.revisions
                .windows(2)
                .all(|pair| pair[0].record_digest < pair[1].record_digest),
            "advisory revisions are unordered or duplicated"
        );
        for revision in &self.revisions {
            ensure!(
                revision.record.digest()? == revision.record_digest,
                "advisory record commitment differs"
            );
            ensure!(
                revision.record.id == self.advisory_id
                    || revision
                        .record
                        .aliases
                        .iter()
                        .any(|alias| alias == &self.advisory_id),
                "advisory record is outside exact equivalence"
            );
            ensure!(
                revision.finding_links.len() <= 100
                    && (revision.finding_links.is_empty() || self.assessment_context.is_some()),
                "advisory finding links lack a bounded assessment context"
            );
            ensure!(
                revision.finding_links.windows(2).all(|pair| (
                    &pair[0].subject_ref,
                    pair[0].finding_key
                ) < (
                    &pair[1].subject_ref,
                    pair[1].finding_key
                )),
                "advisory finding links are unordered or duplicated"
            );
            for link in &revision.finding_links {
                text(&link.subject_ref, 128, "advisory finding subject")?;
                text(&link.component_ref, 128, "advisory finding component")?;
                ensure!(
                    self.assessment_context
                        .as_ref()
                        .and_then(|context| context.subject_ref.as_ref())
                        .is_none_or(|subject| subject == &link.subject_ref),
                    "advisory finding differs from its selected subject"
                );
            }
        }
        ensure!(
            self.next_record.is_none_or(|next| self
                .revisions
                .last()
                .is_some_and(|last| last.record_digest == next)),
            "advisory continuation differs from its last returned revision"
        );
        encoded(self)
    }

    /// Decodes the same strict response consumed by CLI and console.
    ///
    /// # Errors
    /// Returns an error for unknown fields or inconsistent response facts.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let page: Self = decode(bytes, "advisory page")?;
        page.to_bytes()?;
        Ok(page)
    }

    /// Verifies a validated response preserves the caller's exact selection.
    ///
    /// # Errors
    /// Returns an error for changed incarnation, advisory, assessment or continuation.
    pub fn validate_for(&self, query: &AdvisoryQueryV1) -> Result<()> {
        query.validate()?;
        self.to_bytes()?;
        ensure!(
            self.advisory_id == query.advisory_id
                && self.revisions.len() <= query.limit as usize
                && query
                    .resource_scope
                    .as_ref()
                    .is_none_or(|scope| scope == &self.resource_scope),
            "advisory response differs from its resource selection"
        );
        ensure!(
            self.assessment_context
                .as_ref()
                .map(|context| context.assessment_digest)
                == query.assessment_digest
                && self
                    .assessment_context
                    .as_ref()
                    .and_then(|context| context.subject_ref.as_ref())
                    == query.subject_ref.as_ref(),
            "advisory response differs from its historical assessment selection"
        );
        ensure!(
            query.after_record.is_none_or(|after| self
                .revisions
                .iter()
                .all(|revision| revision.record_digest > after)
                && self.next_record.is_none_or(|next| next > after)),
            "advisory response does not advance its continuation"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> AdvisoryQueryV1 {
        AdvisoryQueryV1 {
            schema: "aos.assessment-advisory-query/v1".into(),
            advisory_id: "CVE-2026-12345".into(),
            resource_scope: None,
            assessment_digest: None,
            subject_ref: None,
            after_record: None,
            limit: 10,
        }
    }

    fn page() -> AdvisoryPageV1 {
        let record = AdvisoryRecordV1 {
            schema: aos_assessment::advisory::ADVISORY_RECORD_V1.into(),
            provider: "osv".into(),
            id: "OSV-2026-1".into(),
            modified: "2026-10-08T12:00:00Z".into(),
            withdrawn: Some("2026-10-09T12:00:00Z".into()),
            aliases: vec![query().advisory_id],
            related: vec!["CVE-2026-98765".into()],
            upstream: vec![],
            summary: "Retained withdrawn advisory".into(),
            affected: vec![],
            configuration: None,
            severity: vec![],
            references: vec![],
            source_digest: Sha256Digest::of_bytes("retained raw record"),
        };
        AdvisoryPageV1 {
            schema: "aos.assessment-advisory-page/v1".into(),
            resource_scope: "registry-incarnation".into(),
            advisory_id: query().advisory_id,
            as_of: Timestamp::parse("2026-10-10T00:00:00Z").unwrap(),
            assessment_context: None,
            revisions: vec![AdvisoryRevisionV1 {
                record_digest: record.digest().unwrap(),
                record,
                finding_links: vec![],
            }],
            next_record: None,
        }
    }

    #[test]
    fn preserves_withdrawals_and_never_equates_related_identifiers() {
        let mut page = page();
        let bytes = page.to_bytes().unwrap();
        assert_eq!(AdvisoryPageV1::from_slice(&bytes).unwrap(), page);
        page.validate_for(&query()).unwrap();
        page.advisory_id = "CVE-2026-98765".into();
        assert!(page.to_bytes().is_err());
        page.advisory_id = query().advisory_id;
        page.revisions[0].record.summary = "Changed record".into();
        assert!(page.to_bytes().is_err());
    }

    #[test]
    fn rejects_changed_snapshot_selections_and_unbound_continuations() {
        let mut query = query();
        query.after_record = Some(Sha256Digest::of_bytes("previous record"));
        assert!(query.validate().is_err());
        query.resource_scope = Some("original-registry".into());
        query.validate().unwrap();
        assert!(page().validate_for(&query).is_err());
        query.after_record = None;
        query.resource_scope = None;
        query.subject_ref = Some("subject".into());
        assert!(query.validate().is_err());
        query.assessment_digest = Some(Sha256Digest::of_bytes("admitted assessment"));
        query.validate().unwrap();
        assert!(page().validate_for(&query).is_err());
        query.advisory_id = "CVE-2026-short".into();
        assert!(query.validate().is_err());
        query.advisory_id = "OSV-2026-1".into();
        query.validate().unwrap();
        query.limit = 11;
        assert!(query.validate().is_err());
    }

    #[test]
    fn rejects_undeclared_authority_links_and_duplicate_revisions() {
        let mut page = page();
        let mut value = serde_json::to_value(&page).unwrap();
        value["refresh"] = serde_json::json!(true);
        assert!(AdvisoryPageV1::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
        page.revisions[0].finding_links.push(AdvisoryFindingLink {
            subject_ref: "subject".into(),
            component_ref: "component".into(),
            finding_key: Sha256Digest::of_bytes("finding"),
            applicability: Applicability::Affected,
        });
        assert!(page.to_bytes().is_err());
        page.revisions[0].finding_links.clear();
        page.next_record = Some(page.revisions[0].record_digest);
        page.to_bytes().unwrap();
        page.next_record = Some(Sha256Digest::of_bytes("unrelated cursor"));
        assert!(page.to_bytes().is_err());
        page.next_record = None;
        page.revisions.push(page.revisions[0].clone());
        assert!(page.to_bytes().is_err());
    }
}
