//! Assessment of observations against expanded cases.

use std::collections::BTreeSet;

use anyhow::{Result, bail};

use super::expansion::expand;
use super::selection::select;
use super::{QualificationCase, QualificationObservation};
use crate::digest::Sha256Digest;
use crate::evidence::{EvidenceRecord, GateResult};
use crate::manifest::ReleaseManifestV1;
use crate::plan::ReleasePlan;
use crate::qualification::claims::{
    AssuranceLevel, ClaimDisposition, ClaimOutcome, QualificationClaim,
};
use crate::qualification::environment::EnvironmentInventory;
use crate::qualification::limits::ROLLOUT_FRESHNESS_SECONDS;
use crate::qualification::{EffectiveProfile, QualificationPhase, TargetKind};

/// Validates complete, fresh observations for one destination and hold point.
///
/// `admitted_at` is supplied by the trusted caller, never read from a clock in
/// this pure library. Physical execution and human independence remain the
/// responsibility of the authenticated qualification authorities.
/// `destination` and `effective` have the meaning described for
/// [`assess_observations`].
///
/// # Errors
/// Returns an error for missing, extra, failed, stale, replayed, or incorrectly
/// scoped evidence; missing measurements; an unexercised predecessor; or any
/// [`assess_observations`] error.
pub fn validate_observations(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    destination: Option<&str>,
    phase: QualificationPhase,
    evidence: &[EvidenceRecord],
    admitted_at: &str,
    effective: Option<&EffectiveProfile>,
) -> Result<()> {
    let outcomes = assess_observations(
        plan,
        manifest,
        destination,
        phase,
        evidence,
        admitted_at,
        effective,
    )?;
    if outcomes
        .iter()
        .any(|outcome| outcome.blocks_release && outcome.disposition != ClaimDisposition::Passed)
    {
        bail!("required qualification claim is missing, failed or stale");
    }
    Ok(())
}

/// Derives claim outcomes from scoped evidence at a trusted admission time.
///
/// Cases are those of [`cases`](super::cases) for `destination`: the planned destination's
/// profile, change scope, and soak select them. `effective`, when supplied,
/// must equal the soak and rings frozen for the destination (the plan binds
/// any accepted override); it lets a caller cross-check a separately verified
/// [`crate::profile_override::ProfileOverride`]. Rollout observations must
/// be at most [`ROLLOUT_FRESHNESS_SECONDS`] old; other observations at most
/// [`EXERCISE_MAX_AGE_SECONDS`] old.
///
/// Missing, failed and stale claim evidence remains visible in the result.
/// Malformed evidence and unsuccessful release-wide requirements are errors.
///
/// # Errors
/// Returns an error for unknown, duplicate, malformed or incorrectly bound
/// evidence, invalid inventories, unmet release-wide requirements, an unknown
/// destination, or an effective profile that differs from the plan.
///
/// [`EXERCISE_MAX_AGE_SECONDS`]: crate::qualification::limits::EXERCISE_MAX_AGE_SECONDS
pub fn assess_observations(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    destination: Option<&str>,
    phase: QualificationPhase,
    evidence: &[EvidenceRecord],
    admitted_at: &str,
    effective: Option<&EffectiveProfile>,
) -> Result<Vec<ClaimOutcome>> {
    let expected = expand(plan, manifest, destination, phase, effective)?;
    let now = humantime::parse_rfc3339(admitted_at)?;
    let selection = select(plan, destination, phase, effective)?;
    if evidence.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        bail!("qualification evidence count differs from applicable cases");
    }
    let mut seen = BTreeSet::new();
    let mut outcomes = Vec::new();
    for case in &expected {
        let case_digest = case.digest()?;
        let record = evidence.iter().find(|record| {
            record
                .qualification
                .as_ref()
                .is_some_and(|observation| observation.case_digest == case_digest)
        });
        let Some(record) = record else {
            if let Some(claim) = &case.claim {
                outcomes.push(claim_outcome(case, claim, ClaimDisposition::Missing, None));
                continue;
            }
            bail!("missing qualification case {}", case.id);
        };
        record.validate()?;
        let observation = record
            .qualification
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing structured observation"))?;
        if !seen.insert(&record.id)
            || record.id != format!("qualification/{}", case.id)
            || record.policy_id != case.requirement_id
            || record.policy_digest != case.policy_digest
            || record.platform != case.platform
            || record.subjects != case.subjects
            || observation.predecessor != case.predecessor
        {
            bail!("qualification observation differs from case {}", case.id);
        }
        let actual_checks: BTreeSet<_> = observation.checks.keys().map(String::as_str).collect();
        let required_checks: BTreeSet<_> = case.checks.iter().map(String::as_str).collect();
        if actual_checks != required_checks
            || observation
                .checks
                .values()
                .any(|check| check.detail.trim().is_empty())
        {
            bail!(
                "qualification case {} has missing, unknown, or undocumented acceptance checks",
                case.id
            );
        }
        let start = humantime::parse_rfc3339(&record.started_at)?;
        let finish = humantime::parse_rfc3339(&record.finished_at)?;
        if start > finish
            || finish > now
            || observation.observed_seconds > finish.duration_since(start)?.as_secs()
        {
            bail!("qualification observation has inconsistent or future timestamps");
        }
        let maximum_age = if phase == QualificationPhase::Rollout {
            ROLLOUT_FRESHNESS_SECONDS
        } else {
            selection.exercise_max_age_seconds
        };
        let stale = now.duration_since(finish)?.as_secs() > maximum_age;
        let mut passed = record.result == GateResult::Passed
            && observation.checks.values().all(|check| check.passed);
        if let Some(matrix_passed) = super::validate_matrix_for_case(case, observation)? {
            if (record.result == GateResult::Passed) != matrix_passed {
                bail!("native matrix result differs from exact cell observations");
            }
            passed &= matrix_passed;
        }
        validate_target_scope(case, observation)?;
        if case
            .target
            .as_ref()
            .is_some_and(|target| target.kind == TargetKind::Image)
        {
            let evidence = observation
                .capabilities
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("image execution lacks bound build capabilities"))?;
            let capabilities = evidence.verify(manifest, &case.subjects)?;
            let target = case
                .target
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("image case lacks its environment scope"))?;
            capabilities.satisfies(&target.environment)?;
            let digest = capabilities.digest()?;
            if observation.environment.as_ref().is_some_and(|environment| {
                environment.image_capabilities_digest != Some(digest)
                    || environment
                        .layers
                        .last()
                        .and_then(|layer| layer.kernel_release.as_deref())
                        != Some(capabilities.kernel_release.as_str())
            }) {
                bail!("executed image capabilities differ from the subject's built inventory");
            }
        } else if observation.capabilities.is_some() {
            bail!("capability evidence is inapplicable to this case");
        }
        for (name, bound) in &case.measurements {
            let measured = observation
                .operations
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("missing measurement {name} for {}", case.id))?;
            passed &= *measured >= bound.minimum
                && bound.maximum.is_none_or(|maximum| *measured <= maximum);
        }
        if case.requirement_id == "rollout-observation"
            && (observation.observed_seconds < selection.soak_seconds
                || observation.operations.is_empty()
                || observation.operations.values().any(|count| *count == 0))
        {
            passed = false;
        }
        if let Some(claim) = &case.claim {
            let observed_window = case
                .minimum_observed_seconds
                .is_none_or(|minimum| observation.observed_seconds >= minimum);
            let disposition = if stale {
                ClaimDisposition::Stale
            } else if passed && observed_window {
                ClaimDisposition::Passed
            } else {
                ClaimDisposition::Failed
            };
            let mut outcome = claim_outcome(
                case,
                claim,
                disposition,
                observation
                    .environment
                    .as_ref()
                    .map(EnvironmentInventory::digest)
                    .transpose()?,
            );
            if !stale && passed && !observed_window && claim.minimum_assurance == AssuranceLevel::A3
            {
                outcome.achieved_assurance = AssuranceLevel::A2;
            }
            outcomes.push(outcome);
        } else if stale || !passed {
            bail!("qualification case {} is failed or expired", case.id);
        }
    }
    if seen.len() != evidence.len() {
        bail!("qualification evidence contains unknown or duplicate cases");
    }
    Ok(outcomes)
}

fn claim_outcome(
    case: &QualificationCase,
    claim: &QualificationClaim,
    disposition: ClaimDisposition,
    environment_digest: Option<Sha256Digest>,
) -> ClaimOutcome {
    ClaimOutcome {
        case_id: case.id.clone(),
        claim_id: claim.id.clone(),
        required_assurance: claim.minimum_assurance,
        achieved_assurance: if disposition == ClaimDisposition::Passed {
            claim.minimum_assurance
        } else {
            AssuranceLevel::A0
        },
        disposition,
        blocks_release: claim.blocks_release,
        environment_digest,
    }
}

fn validate_target_scope(
    case: &QualificationCase,
    observation: &QualificationObservation,
) -> Result<()> {
    let Some(target) = &case.target else {
        if observation.environment.is_some() || observation.assessment.is_some() {
            bail!("release/package cases cannot claim target assurance");
        }
        return Ok(());
    };
    let scope = &target.environment;
    let assessment = observation.assessment.as_ref().ok_or_else(|| {
        anyhow::anyhow!("target assurance requires a reviewed compatibility assessment")
    })?;
    let digest = Sha256Digest::of_canonical("aos.release.environment-profile/v1", scope)?;
    if assessment.scope_digest != digest
        || assessment.rationale.trim().is_empty()
        || assessment.reviewer.trim().is_empty()
        || assessment.references.is_empty()
        || assessment
            .references
            .iter()
            .any(|reference| reference.location.trim().is_empty())
    {
        bail!("compatibility assessment lacks its exact scope, rationale or reviewed sources");
    }
    if case
        .claim
        .as_ref()
        .is_some_and(|claim| claim.minimum_assurance == AssuranceLevel::A1)
    {
        if observation.environment.is_some()
            || observation.environment_digest != digest
            || observation.observed_seconds != 0
            || !observation.operations.is_empty()
        {
            bail!("A1 assessment cannot claim a directly executed inventory or measurements");
        }
    } else {
        let environment = observation.environment.as_ref().ok_or_else(|| {
            anyhow::anyhow!("direct execution requires a concrete environment inventory")
        })?;
        if environment.digest()? != observation.environment_digest {
            bail!("execution inventory differs from its evidence identity");
        }
        scope.matches(environment)?;
    }
    Ok(())
}
