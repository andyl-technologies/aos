//! Scoped compatibility claims, measurement obligations and assurance results.
//!
//! Policy contains required assurance. The coordinator derives achieved
//! assurance from validated assessments or executions; it never accepts an
//! executor's self-assigned assurance level.
//!
//! ```text
//! claim -> target scope + requirements + hold point + minimum assurance
//! evidence -> reviewed assessment | exact environment + measured execution
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{QualificationContract, QualificationPhase, QualificationScope, TargetKind};
use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;

/// Evidence strength for a bounded functional claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AssuranceLevel {
    /// No accepted assessment or applicable direct execution.
    A0,
    /// Reviewed compatibility assessment without a direct execution claim.
    A1,
    /// Direct execution of the stated functions on recorded configurations.
    A2,
    /// Complete functional and recovery checks plus class-bound observation.
    A3,
}

/// An authoritative obligation for one target and set of functions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationClaim {
    /// Stable identifier used by reports and release support information.
    pub id: String,
    /// Target whose typed environment defines the compatibility scope.
    pub target: String,
    /// Gate requirements that define the claimed functions.
    pub requirements: Vec<String>,
    /// Minimum evidence strength required at the selected hold point.
    pub minimum_assurance: AssuranceLevel,
    /// Admission hold point; A3 is available only at completion.
    pub phase: QualificationPhase,
    /// Whether a missing or unsuccessful result blocks this release operation.
    pub blocks_release: bool,
}

/// Numeric acceptance bounds enforced independently of textual check results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementRequirement {
    /// Inclusive lower bound, including zero for failure counters.
    pub minimum: u64,
    /// Inclusive upper bound, such as zero for integrity failures.
    pub maximum: Option<u64>,
}

/// A reviewed source supporting a compatibility assessment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentReference {
    /// Retained document or artifact identity.
    pub digest: Sha256Digest,
    /// Public document location or retained-report reference.
    pub location: String,
}

/// Assessment evidence for the exact declared compatibility scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityAssessment {
    /// Canonical digest of the target's typed environment profile.
    pub scope_digest: Sha256Digest,
    /// Account of CPU, ABI, firmware and driver compatibility and exclusions.
    pub rationale: String,
    /// Accountable reviewer identity retained by the evidence authority.
    pub reviewer: String,
    /// Exact reviewed specifications, configurations or driver evidence.
    pub references: Vec<AssessmentReference>,
}

/// Current evidence disposition, independent of its historical assurance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimDisposition {
    /// Required evidence is present and valid.
    Passed,
    /// An execution or assessment recorded failure.
    Failed,
    /// No observation is present for the claim.
    Missing,
    /// Evidence is no longer valid at the admission time.
    Stale,
}

/// Coordinator-derived support result for one expanded claim case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimOutcome {
    /// Exact case identifier, including image variant where applicable.
    pub case_id: String,
    /// Stable claim identifier.
    pub claim_id: String,
    /// Required assurance selected before execution.
    pub required_assurance: AssuranceLevel,
    /// Assurance supported by currently accepted evidence.
    pub achieved_assurance: AssuranceLevel,
    /// Current pass, failure, missing or stale result.
    pub disposition: ClaimDisposition,
    /// Whether an unmet obligation blocks the release operation.
    pub blocks_release: bool,
    /// Exact directly exercised inventory; assessments have no tested inventory.
    pub environment_digest: Option<Sha256Digest>,
}

/// Validates claim references and mandatory operational assurance floors.
///
/// # Errors
/// Returns an error for invalid references, mixed subject kinds, weakened
/// required targets, missing lifecycle obligations or premature A3 claims.
pub fn validate_claims(contract: &QualificationContract) -> Result<()> {
    let mut seen = BTreeSet::new();
    for claim in &contract.claims {
        require_identifier(&claim.id, "qualification claim")?;
        if !seen.insert(&claim.id) || claim.minimum_assurance == AssuranceLevel::A0 {
            bail!("claims require unique identifiers and a positive assurance obligation");
        }
        if claim.phase == QualificationPhase::Build || claim.phase == QualificationPhase::Rollout {
            bail!("target assurance claims are admitted at staging or completion");
        }
        if claim.minimum_assurance == AssuranceLevel::A3
            && claim.phase != QualificationPhase::Complete
        {
            bail!("A3 requires completion of the class observation window");
        }
        let target = contract
            .targets
            .iter()
            .find(|target| target.id == claim.target)
            .ok_or_else(|| anyhow::anyhow!("claim references an unknown target"))?;
        let expected_scope = match target.kind {
            TargetKind::Image => QualificationScope::Images,
            TargetKind::Container => QualificationScope::Containers,
        };
        if claim.requirements.is_empty()
            || claim.requirements.iter().collect::<BTreeSet<_>>().len() != claim.requirements.len()
        {
            bail!("claim requires distinct functional requirements");
        }
        for id in &claim.requirements {
            let requirement = contract
                .requirements
                .iter()
                .find(|requirement| &requirement.id == id)
                .ok_or_else(|| anyhow::anyhow!("claim references an unknown requirement: {id}"))?;
            if requirement.scope != expected_scope || requirement.production_only {
                bail!("claim requirements must share its artifact scope and release applicability");
            }
            if claim.minimum_assurance >= AssuranceLevel::A2 && requirement.phase > claim.phase {
                bail!("execution claim cannot admit a function before its required hold point");
            }
        }
        if claim.minimum_assurance == AssuranceLevel::A3 {
            require_lifecycle(claim, target.kind, true)?;
        }
    }
    for target in contract.targets.iter().filter(|target| target.required) {
        for (phase, assurance) in [
            (QualificationPhase::Staging, AssuranceLevel::A2),
            (QualificationPhase::Complete, AssuranceLevel::A3),
        ] {
            let claim = contract
                .claims
                .iter()
                .find(|claim| {
                    claim.target == target.id
                        && claim.phase == phase
                        && claim.blocks_release
                        && claim.minimum_assurance >= assurance
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "required target {} lacks its {phase:?} assurance obligation",
                        target.id
                    )
                })?;
            require_lifecycle(claim, target.kind, assurance == AssuranceLevel::A3)?;
        }
    }
    Ok(())
}

fn require_lifecycle(claim: &QualificationClaim, kind: TargetKind, complete: bool) -> Result<()> {
    let baseline: &[&str] = match kind {
        TargetKind::Image => &[
            "image-installation",
            "image-lifecycle",
            "image-update-recovery",
        ],
        TargetKind::Container => &["container-lifecycle"],
    };
    for id in baseline
        .iter()
        .copied()
        .chain(complete.then_some(match kind {
            TargetKind::Image => "image-observation",
            TargetKind::Container => "container-observation",
        }))
    {
        if !claim.requirements.iter().any(|value| value == id) {
            bail!("claim {} omits required lifecycle function {id}", claim.id);
        }
    }
    Ok(())
}

/// Combines numeric obligations without weakening overlapping requirements.
///
/// # Errors
/// Returns an error for contradictory lower and upper bounds.
pub fn merge_measurements(
    into: &mut BTreeMap<String, MeasurementRequirement>,
    requirements: &BTreeMap<String, MeasurementRequirement>,
) -> Result<()> {
    for (name, required) in requirements {
        require_identifier(name, "measurement")?;
        let bound = into.entry(name.clone()).or_insert_with(|| required.clone());
        bound.minimum = bound.minimum.max(required.minimum);
        bound.maximum = match (bound.maximum, required.maximum) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        };
        if bound.maximum.is_some_and(|maximum| maximum < bound.minimum) {
            bail!("contradictory measurement bounds for {name}");
        }
    }
    Ok(())
}
