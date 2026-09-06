//! Signed admission of observations after immutable bundle finalization.
//!
//! ```text
//! qualification-admission/v1
//!   phase + registry + plan + manifest + publication receipt + journal
//!   report + policy + authority + admission time
//! ```
//!
//! Later hold points bind the entire predecessor journal, preventing reuse of
//! a health approval for a different rollout range or completion decision.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::Sha256Digest;
use crate::plan::ReleasePlanV1;
use crate::qualification::QualificationPhase;

/// Signed authority decision for a rollout or completion observation report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationAdmissionV1 {
    /// Exact admission schema.
    pub schema_version: String,
    /// Hold point; staging uses its established Hub receipt protocol.
    pub phase: QualificationPhase,
    /// Exact next channel operation; absent for completion.
    pub rollout: Option<QualificationRolloutIntent>,
    /// Exact registry trust domain.
    pub registry: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Digest of the canonical frozen plan.
    pub plan_digest: Sha256Digest,
    /// Finalized manifest payload identity.
    pub manifest_digest: Sha256Digest,
    /// Signed production publication receipt being observed.
    pub publication_receipt_digest: Sha256Digest,
    /// Exact input journal bytes before this transition.
    pub journal_digest: Sha256Digest,
    /// Canonical observation report identity.
    pub report_digest: Sha256Digest,
    /// Frozen shared policy identity.
    pub policy_digest: Sha256Digest,
    /// Planned qualification signing authority.
    pub authority_id: String,
    /// Time at which the authority evaluated evidence validity.
    pub admitted_at: String,
}

impl QualificationAdmissionV1 {
    /// Requires a properly scoped, current authority decision.
    ///
    /// # Errors
    /// Returns an error for identity drift, a wrong phase, a stale/future
    /// decision, or an authority outside the frozen qualification role.
    pub fn validate(&self, plan: &ReleasePlanV1, now: &str) -> Result<()> {
        if self.schema_version != "aos.release.qualification-admission/v1"
            || !matches!(
                self.phase,
                QualificationPhase::Rollout | QualificationPhase::Complete
            )
            || self.registry != plan.registry
            || self.release_id != plan.release_id
            || self.plan_digest != Sha256Digest::of_bytes(&crate::canonical::to_vec(plan)?)
            || self.policy_digest != plan.public_evidence_policy_digest
        {
            bail!("qualification admission differs from the frozen release");
        }
        match (&self.rollout, self.phase) {
            (Some(intent), QualificationPhase::Rollout)
                if intent.first_partition <= intent.last_partition
                    && intent.last_partition <= 255
                    && plan.intended_channels.iter().any(|planned| {
                        planned.channel == intent.channel
                            && intent.first_partition >= planned.first_partition
                            && intent.last_partition <= planned.last_partition
                    }) => {}
            (None, QualificationPhase::Complete) => {}
            _ => bail!("qualification admission lacks its exact planned rollout intent"),
        }
        let role = plan
            .signers
            .iter()
            .find(|role| role.role == crate::signing::SignerRole::Qualification)
            .ok_or_else(|| anyhow::anyhow!("missing qualification authority"))?;
        if role.threshold != 1 || role.key_ids.as_slice() != [self.authority_id.as_str()] {
            bail!("qualification admission signer differs from the planned authority");
        }
        let admitted = humantime::parse_rfc3339(&self.admitted_at)?;
        let now = humantime::parse_rfc3339(now)?;
        if admitted > now || now.duration_since(admitted)?.as_secs() > 600 {
            bail!("live qualification admission must be no more than ten minutes old");
        }
        Ok(())
    }
}

/// Independent review of the exact observation report, signed as a receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReviewV1 {
    /// Exact review schema.
    pub schema_version: String,
    /// Exact canonical frozen-plan identity.
    pub plan_digest: Sha256Digest,
    /// Reviewed canonical report identity.
    pub report_digest: Sha256Digest,
    /// Public reviewer signing identity from the release-evidence role.
    pub authority_id: String,
    /// Affirmative acceptance after inspection of the retained observations.
    pub accepted: bool,
}

/// Verifies independent acceptance of an exact report by planned release-evidence keys.
///
/// # Errors
/// Returns an error for invalid signatures, duplicate reviewers, wrong report/plan
/// identities, rejected decisions, or an unsatisfied independent review threshold.
pub fn verify_reviews(
    plan: &ReleasePlanV1,
    report: &[u8],
    reviews: &[Vec<u8>],
    keys: &[crate::signing::TrustedEd25519Key],
) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let Some(contract) = &plan.qualification else {
        return Ok(());
    };
    if !contract
        .thresholds_for(plan.release_class)?
        .require_independent_review
        && reviews.is_empty()
    {
        return Ok(());
    }
    let role = plan
        .signers
        .iter()
        .find(|role| role.role == crate::signing::SignerRole::ReleaseEvidence)
        .ok_or_else(|| anyhow::anyhow!("missing review authority role"))?;
    let trusted: BTreeMap<_, _> = keys
        .iter()
        .map(|key| (key.key_id.clone(), key.public_key))
        .collect();
    let mut reviewers = BTreeSet::new();
    for bytes in reviews {
        let (key, review): (String, QualificationReviewV1) =
            crate::receipt::verify_signed_receipt_with_key(bytes, &trusted)?;
        if review.schema_version != "aos.release.qualification-review/v1"
            || !review.accepted
            || review.authority_id != key
            || !role.key_ids.contains(&key)
            || !reviewers.insert(key)
            || review.plan_digest != Sha256Digest::of_bytes(&crate::canonical::to_vec(plan)?)
            || review.report_digest != Sha256Digest::of_bytes(report)
        {
            bail!("independent review differs from the planned authority or exact report");
        }
    }
    if reviewers.len() < usize::from(role.threshold) {
        bail!("qualification requires the independent release-evidence review threshold");
    }
    Ok(())
}

/// Next channel operation reviewed together with the fresh health observations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRolloutIntent {
    /// Planned channel name.
    pub channel: String,
    /// Expected public generation before the operation.
    pub prior_generation: u64,
    /// First partition to advance.
    pub first_partition: u16,
    /// Last partition to advance, inclusive.
    pub last_partition: u16,
}
