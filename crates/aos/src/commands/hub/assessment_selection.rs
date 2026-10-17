//! Bounded resolution of ergonomic Hub scan selectors into a frozen submission.
//!
//! Status pages establish package membership, never source evidence or scan
//! authority. All pages must agree on the resource incarnation, inventory
//! revision and decision policy before any scan admission RPC is sent.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment_runtime::application::{AssessmentStatusV1, StatusQueryV1};
use aos_assessment_runtime::control::ScanSubmissionV1;
use aos_assessment_runtime::scan::ScanLimits;
use aos_contract::Sha256Digest;
use aos_remote::{HubClient, hub_rpc, hub_types};

use crate::cli::{HubAssessmentScanSelectionArgs, assessment_profiles};

const MAX_ENUMERATED_SUBJECTS: usize = 4096;
const MAX_SELECTION_PAGES: usize = 64;

/// Resolves a complete exact selection before requesting any source work.
///
/// # Errors
/// Returns an error for unavailable or inconsistent inventory pages, excessive
/// enumeration, missing package selectors or invalid submission bounds.
pub(super) async fn resolve(
    client: &HubClient,
    registry: &str,
    args: &HubAssessmentScanSelectionArgs,
) -> Result<ScanSubmissionV1> {
    let profiles = assessment_profiles(&args.profiles);
    let mut selection = Selection::new(profiles.clone(), &args.packages);
    let mut query = StatusQueryV1 {
        schema: "aos.assessment-status-query/v1".into(),
        profiles,
        limit: 100,
        after_subject: None,
        inventory_digest: None,
        policy_digest: None,
    };
    loop {
        let response = client
            .call_topology(
                hub_rpc::GetAssessmentStatus,
                &hub_types::AssessmentStatusRequest {
                    registry_slug: registry.into(),
                    query_json: serde_json::to_vec(&query)?,
                },
            )
            .await?;
        let page = AssessmentStatusV1::from_slice(&response.document_json)?;
        selection.push(&page)?;
        query.inventory_digest = Some(page.inventory_digest);
        query.policy_digest = Some(page.policy_digest);
        query.after_subject = page.next_subject;
        if query.after_subject.is_none() {
            break;
        }
    }
    selection.finish(args)
}

struct Selection {
    profiles: Vec<Profile>,
    packages: BTreeSet<String>,
    matched_packages: BTreeSet<String>,
    context: Option<(String, u64, Sha256Digest, Sha256Digest)>,
    last_subject: Option<String>,
    next_subject: Option<String>,
    subjects: Vec<String>,
    enumerated: usize,
    pages: usize,
}

impl Selection {
    fn new(profiles: Vec<Profile>, packages: &[String]) -> Self {
        Self {
            profiles,
            packages: packages.iter().cloned().collect(),
            matched_packages: BTreeSet::new(),
            context: None,
            last_subject: None,
            next_subject: None,
            subjects: Vec::new(),
            enumerated: 0,
            pages: 0,
        }
    }

    fn push(&mut self, page: &AssessmentStatusV1) -> Result<()> {
        page.to_bytes()?;
        ensure!(
            self.pages == 0 || self.next_subject.is_some(),
            "Hub returned a page after a complete selection"
        );
        let context = (
            page.resource_scope.clone(),
            page.inventory_revision,
            page.inventory_digest,
            page.policy_digest,
        );
        ensure!(
            self.context
                .as_ref()
                .is_none_or(|expected| expected == &context),
            "Hub inventory changed during selection; restart with a new request identity"
        );
        ensure!(
            page.subjects.first().is_none_or(|subject| {
                self.last_subject
                    .as_ref()
                    .is_none_or(|previous| previous < &subject.subject_ref)
            }),
            "Hub selection pagination did not advance monotonically"
        );
        let enumerated = self
            .enumerated
            .checked_add(page.subjects.len())
            .context("Hub selection size overflow")?;
        ensure!(
            enumerated <= MAX_ENUMERATED_SUBJECTS && self.pages < MAX_SELECTION_PAGES,
            "Hub selection exceeds the bounded CLI enumeration; use an exact submission file"
        );
        for subject in &page.subjects {
            ensure!(
                subject
                    .profiles
                    .iter()
                    .map(|status| status.profile)
                    .eq(self.profiles.iter().copied()),
                "Hub selection omitted or changed a requested profile"
            );
            if self.packages.is_empty() || self.packages.contains(&subject.package_coordinate) {
                self.subjects.push(subject.subject_ref.clone());
                self.matched_packages
                    .insert(subject.package_coordinate.clone());
            }
        }
        self.context = Some(context);
        self.last_subject = page
            .subjects
            .last()
            .map(|subject| subject.subject_ref.clone())
            .or(self.last_subject.take());
        self.next_subject = page.next_subject.clone();
        self.enumerated = enumerated;
        self.pages += 1;
        Ok(())
    }

    fn finish(self, args: &HubAssessmentScanSelectionArgs) -> Result<ScanSubmissionV1> {
        ensure!(
            self.pages > 0 && self.next_subject.is_none(),
            "Hub selection is incomplete"
        );
        ensure!(
            !self.subjects.is_empty() && self.packages.is_subset(&self.matched_packages),
            "assessment selection contains an unknown or unassessable package coordinate"
        );
        let (_, inventory_revision, inventory_digest, policy_digest) =
            self.context.context("Hub selection has no inventory")?;
        let submission = ScanSubmissionV1 {
            schema: "aos.assessment-scan-submission/v1".into(),
            inventory_revision,
            inventory_digest,
            policy_digest,
            subjects: self.subjects,
            profiles: self.profiles,
            freshness: args
                .freshness
                .map(Into::into)
                .unwrap_or(FreshnessMode::RefreshStale),
            idempotency_key: args
                .idempotency_key
                .clone()
                .context("Hub scan requires an idempotency key")?,
            limits: ScanLimits::default(),
        };
        ScanSubmissionV1::from_slice(&serde_json::to_vec(&submission)?)?;
        Ok(submission)
    }
}

#[cfg(test)]
mod tests;
