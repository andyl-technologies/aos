//! Exact subject expansion and observations for shared release qualification.
//!
//! An observation names a canonical case digest. Cases bind the phase,
//! requirement, artifact population, target configuration, and predecessor.
//! Reports for a fixture, another platform, or a different phase cannot satisfy
//! a release case even when they reuse the same human-readable gate name.
//!
//! ```text
//! case -> requirement + target + subjects + predecessor
//! observation -> case digest + checks + environment + executor + measurements
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactKind;
use crate::digest::Sha256Digest;
use crate::evidence::{EvidenceRecord, GateResult};
use crate::manifest::ReleaseManifestV1;
use crate::plan::ReleasePlanV1;
use crate::platform::{MatrixCell, Platform};
use crate::qualification::claims::{
    AssuranceLevel, CompatibilityAssessment, MeasurementRequirement, QualificationClaim,
    merge_measurements,
};
use crate::qualification::claims::{ClaimDisposition, ClaimOutcome};
use crate::qualification::environment::EnvironmentInventory;
use crate::qualification::{
    CONTRACT_V2, QualificationMethod, QualificationPhase, QualificationRequirement,
    QualificationScope, QualificationTarget, TargetKind,
};

/// A prior accepted snapshot selected before qualification begins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationPredecessor {
    /// Same trust domain as the candidate.
    pub registry: String,
    /// Immutable prior release identity.
    pub release_id: String,
    /// Independently verified prior manifest payload digest.
    pub manifest_digest: Sha256Digest,
}

/// One exact required execution, expanded from a frozen plan and manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCase {
    /// Version of current case semantics; absent in archived v1 cases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    /// Scoped assurance obligation, when this case exercises a target claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<QualificationClaim>,
    /// Numeric bounds that must hold in this exact execution environment.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub measurements: BTreeMap<String, MeasurementRequirement>,
    /// Required observation window for this configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_observed_seconds: Option<u64>,
    /// Unique name within a phase.
    pub id: String,
    /// Stable shared requirement identity.
    pub requirement_id: String,
    /// Exact class-bound requirement policy digest.
    pub policy_digest: Sha256Digest,
    /// Canonical frozen-plan identity, including release and trust domain.
    pub plan_digest: Sha256Digest,
    /// Canonical identity of the full artifact records for the selected subjects.
    pub subjects_digest: Sha256Digest,
    /// Release transition authorized by the observation.
    pub phase: QualificationPhase,
    /// Exact target platform, or none for release-wide evidence.
    pub platform: Option<Platform>,
    /// Direct package criticality; runtime dependencies inherit their consumers' obligations.
    pub package_role: Option<crate::qualification::PackageRole>,
    /// Public reference machine/runtime configuration, where applicable.
    pub target: Option<QualificationTarget>,
    /// Sorted exact artifact ids; package tests never cover unrelated packages.
    pub subjects: Vec<String>,
    /// Every required acceptance condition.
    pub checks: Vec<String>,
    /// Automated or operator exercise.
    pub method: QualificationMethod,
    /// Prior snapshot for image transition tests.
    pub predecessor: Option<QualificationPredecessor>,
}

impl QualificationCase {
    /// Computes the identity that an observation must bind.
    ///
    /// # Errors
    /// Returns an error for unsupported case semantics or failed canonical encoding.
    pub fn digest(&self) -> Result<Sha256Digest> {
        match self.schema_version.as_deref() {
            None if self.claim.is_none()
                && self.measurements.is_empty()
                && self.minimum_observed_seconds.is_none()
                && self
                    .target
                    .as_ref()
                    .is_none_or(|target| target.environment.is_none()) => {}
            Some("aos.release.qualification-case/v2") => {}
            _ => bail!("qualification case schema does not support its assurance semantics"),
        }
        Sha256Digest::of_canonical(
            self.schema_version
                .as_deref()
                .unwrap_or("aos.release.qualification-case/v1"),
            self,
        )
    }
}

/// An individual acceptance observation, retaining the explanation on failure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckObservation {
    /// Whether the acceptance condition held.
    pub passed: bool,
    /// Public diagnostic or reference into the retained report.
    pub detail: String,
}

/// Structured evidence that accompanies a signed gate record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationObservation {
    /// Final image metadata bound to the exact artifact exercised by this case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<crate::qualification::capabilities::CapabilityEvidence>,
    /// Concrete directly exercised environment, required for current target executions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentInventory>,
    /// Reviewed compatibility assessment, permitted only for A1 cases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<CompatibilityAssessment>,
    /// Exact expanded case identity.
    pub case_digest: Sha256Digest,
    /// Immutable executor closure identity.
    pub executor_digest: Sha256Digest,
    /// Digest of recorded actual hardware, firmware, runtime, and tool identities.
    pub environment_digest: Sha256Digest,
    /// Exact declared acceptance checks, with no omitted or unknown entries.
    pub checks: BTreeMap<String, CheckObservation>,
    /// Duration measured by the executing environment.
    pub observed_seconds: u64,
    /// Workload operation denominators; durations alone do not prove workload execution.
    pub operations: BTreeMap<String, u64>,
    /// Prior snapshot actually exercised, when required by the case.
    pub predecessor: Option<QualificationPredecessor>,
}

/// Expands only applicable cases for one phase from the frozen artifact matrix.
///
/// # Errors
/// Returns an error for absent policy, missing required image/OCI artifacts,
/// missing predecessor, empty subjects, or noncanonical requirement identities.
pub fn cases(
    plan: &ReleasePlanV1,
    manifest: &ReleaseManifestV1,
    phase: QualificationPhase,
) -> Result<Vec<QualificationCase>> {
    plan.validate()?;
    let contract = plan
        .qualification
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("archival plan has no shared qualification contract"))?;
    let current = contract.schema_version == CONTRACT_V2;
    let qualification_snapshot = plan.is_qualification_snapshot();
    let mut requirements: Vec<_> = contract
        .selected(plan.release_class)
        .filter(|gate| gate.phase == phase)
        .filter(|gate| !qualification_snapshot || gate.id != "image-update-recovery")
        .filter(|gate| {
            !current
                || !matches!(
                    gate.scope,
                    QualificationScope::Images | QualificationScope::Containers
                )
        })
        .cloned()
        .map(|requirement| (requirement, None))
        .collect();
    for claim in contract
        .claims
        .iter()
        .filter(|claim| claim.phase == phase)
        .filter(|claim| {
            !qualification_snapshot
                || !claim
                    .requirements
                    .iter()
                    .any(|requirement| requirement == "image-update-recovery")
        })
    {
        let target = contract
            .targets
            .iter()
            .find(|target| target.id == claim.target)
            .ok_or_else(|| anyhow::anyhow!("claim target is absent"))?;
        let mut checks = BTreeSet::new();
        let mut measurements = BTreeMap::new();
        for id in &claim.requirements {
            let requirement = contract
                .requirements
                .iter()
                .find(|requirement| &requirement.id == id)
                .ok_or_else(|| anyhow::anyhow!("claim requirement is absent"))?;
            checks.extend(requirement.checks.iter().cloned());
            merge_measurements(&mut measurements, &requirement.measurements)?;
        }
        if claim.minimum_assurance == AssuranceLevel::A1 {
            checks = BTreeSet::from(["reviewed-compatibility-assessment".to_owned()]);
            measurements.clear();
        }
        requirements.push((
            QualificationRequirement {
                id: format!("claim-{}", claim.id),
                phase,
                scope: match target.kind {
                    TargetKind::Image => QualificationScope::Images,
                    TargetKind::Container => QualificationScope::Containers,
                },
                method: if claim.minimum_assurance == AssuranceLevel::A1 {
                    QualificationMethod::Operator
                } else {
                    QualificationMethod::Automated
                },
                production_only: false,
                checks: checks.into_iter().collect(),
                measurements,
                regressions: Vec::new(),
                invalidated_by: Vec::new(),
            },
            Some(claim.clone()),
        ));
    }
    let mut result = Vec::new();
    for (requirement, claim) in requirements {
        let gate = plan
            .gates
            .iter()
            .find(|gate| gate.policy_id == requirement.id)
            .ok_or_else(|| anyhow::anyhow!("missing planned requirement {}", requirement.id))?;
        let mut add = |suffix: String,
                       platform: Option<Platform>,
                       target: Option<QualificationTarget>,
                       mut subjects: Vec<String>|
         -> Result<()> {
            subjects.sort();
            subjects.dedup();
            if subjects.is_empty() {
                bail!(
                    "qualification requirement {} has no artifacts for {suffix}",
                    requirement.id
                );
            }
            let predecessor = if requirement.id == "image-update-recovery"
                || claim.as_ref().is_some_and(|claim| {
                    claim.minimum_assurance >= AssuranceLevel::A2
                        && claim
                            .requirements
                            .iter()
                            .any(|id| id == "image-update-recovery")
                }) {
                Some(plan.qualification_predecessor.clone().ok_or_else(|| {
                    anyhow::anyhow!("image update qualification requires a frozen predecessor")
                })?)
            } else {
                None
            };
            let package_role = if requirement.scope == QualificationScope::Packages {
                let (name, _) = suffix
                    .rsplit_once('/')
                    .ok_or_else(|| anyhow::anyhow!("invalid package case identity"))?;
                Some(
                    contract
                        .package_rules
                        .iter()
                        .find(|rule| rule.name == name)
                        .ok_or_else(|| {
                            anyhow::anyhow!("package case lacks its criticality classification")
                        })?
                        .role,
                )
            } else {
                None
            };
            let artifacts = subjects
                .iter()
                .map(|id| {
                    manifest
                        .artifacts
                        .iter()
                        .find(|artifact| artifact.id == *id)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "qualification subject {id} has no final artifact record"
                            )
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            let subjects_digest =
                Sha256Digest::of_canonical("aos.release.qualification-subjects/v1", &artifacts)?;
            result.push(QualificationCase {
                schema_version: current.then(|| "aos.release.qualification-case/v2".to_owned()),
                claim: claim.clone(),
                measurements: requirement.measurements.clone(),
                minimum_observed_seconds: if claim
                    .as_ref()
                    .is_some_and(|claim| claim.minimum_assurance == AssuranceLevel::A3)
                {
                    Some(contract.thresholds_for(plan.release_class)?.soak_seconds)
                } else {
                    None
                },
                id: format!("{}/{suffix}", requirement.id),
                requirement_id: requirement.id.clone(),
                policy_digest: gate.policy_digest,
                plan_digest: Sha256Digest::of_bytes(crate::canonical::to_vec(plan)?),
                subjects_digest,
                phase,
                platform,
                package_role,
                target,
                subjects,
                checks: requirement.checks.clone(),
                method: requirement.method,
                predecessor,
            });
            Ok(())
        };
        match requirement.scope {
            QualificationScope::Release => add(
                "release".to_owned(),
                None,
                None,
                manifest
                    .artifacts
                    .iter()
                    // The plan is a private control input already bound by
                    // plan_digest, not an anonymously downloadable object.
                    // Evidence cannot include itself in its own subject hash.
                    .filter(|artifact| {
                        !matches!(
                            artifact.kind,
                            ArtifactKind::ReleasePlan | ArtifactKind::Evidence
                        )
                    })
                    .map(|artifact| artifact.id.clone())
                    .collect(),
            )?,
            QualificationScope::Packages => {
                for package in &manifest.packages {
                    for cell in &package.platforms {
                        if let MatrixCell::Artifact { artifact } = &cell.decision {
                            add(
                                format!("{}/{}", package.name, cell.platform),
                                Some(cell.platform),
                                None,
                                artifact.artifact_ids.clone(),
                            )?;
                        }
                    }
                }
            }
            QualificationScope::Images => {
                for target in contract
                    .targets
                    .iter()
                    .filter(|target| target.kind == TargetKind::Image)
                    .filter(|target| claim.as_ref().is_none_or(|claim| claim.target == target.id))
                {
                    for image in &manifest.images {
                        let cell = image
                            .platforms
                            .iter()
                            .find(|cell| cell.platform == target.platform);
                        match cell.map(|cell| &cell.decision) {
                            Some(MatrixCell::Artifact { artifact }) => add(
                                format!("{}/{}", image.system_variant, target.id),
                                Some(target.platform),
                                Some(target.clone()),
                                artifact.artifact_ids.clone(),
                            )?,
                            _ if target.required => {
                                bail!("missing required image target {}", target.id)
                            }
                            _ => {}
                        }
                    }
                    if target.required && manifest.images.is_empty() {
                        bail!("missing required image matrix");
                    }
                }
            }
            QualificationScope::Containers => {
                for target in contract
                    .targets
                    .iter()
                    .filter(|target| target.kind == TargetKind::Container)
                    .filter(|target| claim.as_ref().is_none_or(|claim| claim.target == target.id))
                {
                    let subjects: Vec<_> = manifest
                        .artifacts
                        .iter()
                        .filter(|artifact| {
                            artifact.kind == ArtifactKind::OciIndex
                                || (matches!(
                                    artifact.kind,
                                    ArtifactKind::OciManifest | ArtifactKind::OciBlob
                                ) && artifact.platform == Some(target.platform))
                        })
                        .map(|artifact| artifact.id.clone())
                        .collect();
                    let has_manifest = manifest.artifacts.iter().any(|artifact| {
                        artifact.kind == ArtifactKind::OciManifest
                            && artifact.platform == Some(target.platform)
                    });
                    let has_index = manifest
                        .artifacts
                        .iter()
                        .any(|artifact| artifact.kind == ArtifactKind::OciIndex);
                    if target.required && (!has_manifest || !has_index) {
                        bail!(
                            "missing required OCI index/platform manifest for {}",
                            target.id
                        );
                    }
                    if has_manifest && has_index {
                        add(
                            target.id.clone(),
                            Some(target.platform),
                            Some(target.clone()),
                            subjects,
                        )?;
                    }
                }
            }
        }
    }
    result.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(result)
}

/// Validates complete, fresh observations for one exact release hold point.
///
/// `admitted_at` is supplied by the trusted caller, never read from a clock in
/// this pure library. Physical execution and human independence remain the
/// responsibility of the authenticated qualification authorities.
///
/// # Errors
/// Returns an error for missing, extra, failed, stale, replayed, or incorrectly
/// scoped evidence; missing measurements; or an unexercised predecessor.
pub fn validate_observations(
    plan: &ReleasePlanV1,
    manifest: &ReleaseManifestV1,
    phase: QualificationPhase,
    evidence: &[EvidenceRecord],
    admitted_at: &str,
) -> Result<()> {
    let outcomes = assess_observations(plan, manifest, phase, evidence, admitted_at)?;
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
/// Missing, failed and stale claim evidence remains visible in the result.
/// Malformed evidence and unsuccessful release-wide requirements are errors.
///
/// # Errors
/// Returns an error for unknown, duplicate, malformed or incorrectly bound
/// evidence, invalid inventories or unmet release-wide requirements.
pub fn assess_observations(
    plan: &ReleasePlanV1,
    manifest: &ReleaseManifestV1,
    phase: QualificationPhase,
    evidence: &[EvidenceRecord],
    admitted_at: &str,
) -> Result<Vec<ClaimOutcome>> {
    let expected = cases(plan, manifest, phase)?;
    let now = humantime::parse_rfc3339(admitted_at)?;
    let contract = plan
        .qualification
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing qualification contract"))?;
    let thresholds = contract.thresholds_for(plan.release_class)?;
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
            600
        } else {
            thresholds.exercise_max_age_seconds
        };
        let stale = now.duration_since(finish)?.as_secs() > maximum_age;
        let mut passed = record.result == GateResult::Passed
            && observation.checks.values().all(|check| check.passed);
        if case.schema_version.is_some() {
            validate_current_scope(case, observation)?;
            if case
                .target
                .as_ref()
                .is_some_and(|target| target.kind == TargetKind::Image)
            {
                let evidence = observation.capabilities.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("image execution lacks bound build capabilities")
                })?;
                let capabilities = evidence.verify(manifest, &case.subjects)?;
                let scope = case
                    .target
                    .as_ref()
                    .and_then(|target| target.environment.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("image case lacks its environment scope"))?;
                capabilities.satisfies(scope)?;
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
        } else if observation.environment.is_some()
            || observation.assessment.is_some()
            || observation.capabilities.is_some()
        {
            bail!("archival cases cannot carry current assurance evidence");
        }
        if case.requirement_id == "rollout-observation"
            && (observation.observed_seconds < thresholds.soak_seconds
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

fn validate_current_scope(
    case: &QualificationCase,
    observation: &QualificationObservation,
) -> Result<()> {
    let Some(target) = &case.target else {
        if observation.environment.is_some() || observation.assessment.is_some() {
            bail!("release/package cases cannot claim target assurance");
        }
        return Ok(());
    };
    let scope = target
        .environment
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("current target has no typed environment"))?;
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
