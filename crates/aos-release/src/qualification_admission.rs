//! Signed admission of observations after immutable bundle finalization.
//!
//! ```text
//! qualification-admission
//!   phase + destination + rollout(destination, ring, partitions, generation)
//!   registry + plan + manifest + publication receipt + journal
//!   report + policy + authority + admission time
//! ```
//!
//! Later hold points bind the entire predecessor journal, preventing reuse of
//! a health approval for a different rollout range or completion decision.
//! Admissions name the destination, and a rollout names the one-based ring
//! whose exact partition range the plan froze.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::Sha256Digest;
use crate::plan::ReleasePlan;
use crate::qualification::QualificationPhase;
use crate::qualification::limits::ROLLOUT_FRESHNESS_SECONDS;

/// Schema of admissions scoped to one destination and rollout ring.
pub const QUALIFICATION_ADMISSION: &str = "aos.release.qualification-admission/v1";

/// Schema of an independent review of one exact observation report.
pub const QUALIFICATION_REVIEW: &str = "aos.release.qualification-review/v1";

/// Signed authority decision for a rollout or completion observation report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationAdmission {
    /// Exact admission schema.
    pub schema_version: String,
    /// Hold point; staging uses its established publication receipt protocol.
    pub phase: QualificationPhase,
    /// Planned destination observed.
    pub destination: String,
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

impl QualificationAdmission {
    /// Requires a properly scoped, current authority decision.
    ///
    /// The admission must name a planned destination; a rollout admission must
    /// name one of that destination's rings with the exact partition range the
    /// plan froze.
    ///
    /// # Errors
    /// Returns an error for identity drift, a wrong phase or destination, a
    /// rollout outside the planned rings, a stale/future decision, or an
    /// authority outside the frozen qualification role.
    pub fn validate(&self, plan: &ReleasePlan, now: &str) -> Result<()> {
        if self.schema_version != QUALIFICATION_ADMISSION
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
        let destination = plan.destination(&self.destination)?;
        match (&self.rollout, self.phase) {
            (Some(intent), QualificationPhase::Rollout) => intent.validate_for(destination)?,
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
        if admitted > now || now.duration_since(admitted)?.as_secs() > ROLLOUT_FRESHNESS_SECONDS {
            bail!("live qualification admission must be no more than ten minutes old");
        }
        Ok(())
    }
}

/// Independent review of the exact observation report, signed as a receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReview {
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
/// The required number of distinct accepting reviewers is the
/// `review_threshold` of the destination's profile (zero requires none, but
/// any supplied review must still verify).
///
/// # Errors
/// Returns an error for invalid signatures, duplicate reviewers, wrong report/plan
/// identities, rejected decisions, an unknown or missing destination, or an
/// unsatisfied independent review threshold.
pub fn verify_reviews(
    plan: &ReleasePlan,
    destination: &str,
    report: &[u8],
    reviews: &[Vec<u8>],
    keys: &[crate::signing::TrustedEd25519Key],
) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let role = plan
        .signers
        .iter()
        .find(|role| role.role == crate::signing::SignerRole::ReleaseEvidence)
        .ok_or_else(|| anyhow::anyhow!("missing review authority role"))?;
    let planned = plan.destination(destination)?;
    let required = usize::from(
        plan.qualification
            .profile(&planned.profile)?
            .review_threshold,
    );
    if required == 0 && reviews.is_empty() {
        return Ok(());
    }

    let trusted: BTreeMap<_, _> = keys
        .iter()
        .map(|key| (key.key_id.clone(), key.public_key))
        .collect();
    let plan_digest = Sha256Digest::of_bytes(&crate::canonical::to_vec(plan)?);
    let report_digest = Sha256Digest::of_bytes(report);
    let mut reviewers = BTreeSet::new();
    for bytes in reviews {
        let (key, review): (String, QualificationReview) =
            crate::receipt::verify_signed_receipt_with_key(bytes, &trusted)?;
        if review.schema_version != QUALIFICATION_REVIEW
            || !review.accepted
            || review.authority_id != key
            || !role.key_ids.contains(&key)
            || !reviewers.insert(key)
            || review.plan_digest != plan_digest
            || review.report_digest != report_digest
        {
            bail!("independent review differs from the planned authority or exact report");
        }
    }
    if reviewers.len() < required {
        bail!(
            "qualification requires {required} independent release-evidence reviews; {} verified",
            reviewers.len()
        );
    }
    Ok(())
}

/// Next channel operation reviewed together with the fresh health observations.
///
/// The intent names a planned destination and one-based ring, the exact
/// inclusive partition range, and the expected prior channel generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRolloutIntent {
    /// Planned destination whose channel advances.
    pub destination: String,
    /// One-based rollout ring of the destination.
    pub ring: u16,
    /// Expected public generation before the operation.
    pub prior_generation: u64,
    /// First partition to advance.
    pub first_partition: u16,
    /// Last partition to advance, inclusive.
    pub last_partition: u16,
}

impl QualificationRolloutIntent {
    /// Constructs the exact intent for one ring of a planned destination.
    ///
    /// # Errors
    /// Returns an error when `ring` is zero or beyond the destination's rings.
    pub fn for_ring(
        destination: &crate::plan::PlannedDestination,
        ring: u16,
        prior_generation: u64,
    ) -> Result<Self> {
        let (first_partition, last_partition) = destination.ring_range(ring)?;
        Ok(Self {
            destination: destination.name.clone(),
            ring,
            prior_generation,
            first_partition,
            last_partition,
        })
    }

    /// Requires this intent to name exactly one ring of `destination`.
    ///
    /// # Errors
    /// Returns an error for a different destination, an out-of-range ring, or
    /// a partition range that differs from the ring's planned range.
    pub fn validate_for(&self, destination: &crate::plan::PlannedDestination) -> Result<()> {
        if self.destination != destination.name {
            bail!(
                "rollout intent does not name destination {}",
                destination.name
            );
        }
        let ring = self.ring;
        let (first, last) = destination.ring_range(ring)?;
        if (self.first_partition, self.last_partition) != (first, last) {
            bail!(
                "rollout intent partitions {}..={} differ from ring {ring} ({first}..={last}) of {}",
                self.first_partition,
                self.last_partition,
                destination.name
            );
        }
        Ok(())
    }
}
