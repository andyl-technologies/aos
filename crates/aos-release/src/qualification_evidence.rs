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
use crate::qualification::{
    QualificationMethod, QualificationPhase, QualificationScope, QualificationTarget, TargetKind,
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
    /// Unique name within a phase.
    pub id: String,
    /// Stable shared requirement identity.
    pub requirement_id: String,
    /// Exact class-bound requirement policy digest.
    pub policy_digest: Sha256Digest,
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
    /// Returns an error when the case cannot be canonically encoded.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Sha256Digest::of_canonical("aos.release.qualification-case/v1", self)
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
    let contract = plan
        .qualification
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("archival plan has no shared qualification contract"))?;
    let mut result = Vec::new();
    for requirement in contract
        .selected(plan.release_class)
        .filter(|gate| gate.phase == phase)
    {
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
            let predecessor = if requirement.id == "image-update-recovery" {
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
            result.push(QualificationCase {
                id: format!("{}/{suffix}", requirement.id),
                requirement_id: requirement.id.clone(),
                policy_digest: gate.policy_digest,
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
                    .filter(|artifact| artifact.kind != ArtifactKind::Evidence)
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
    let expected = cases(plan, manifest, phase)?;
    let now = humantime::parse_rfc3339(admitted_at)?;
    let contract = plan
        .qualification
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing qualification contract"))?;
    let thresholds = contract.thresholds_for(plan.release_class)?;
    if evidence.len() != expected.len() || evidence.windows(2).any(|pair| pair[0].id >= pair[1].id)
    {
        bail!("qualification evidence count differs from applicable cases");
    }
    let mut seen = BTreeSet::new();
    for case in &expected {
        let case_digest = case.digest()?;
        let record = evidence
            .iter()
            .find(|record| {
                record
                    .qualification
                    .as_ref()
                    .is_some_and(|observation| observation.case_digest == case_digest)
            })
            .ok_or_else(|| anyhow::anyhow!("missing qualification case {}", case.id))?;
        record.validate()?;
        let observation = record
            .qualification
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing structured observation"))?;
        if !seen.insert(&record.id)
            || record.id != format!("qualification/{}", case.id)
            || record.result != GateResult::Passed
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
                .any(|check| !check.passed || check.detail.trim().is_empty())
        {
            bail!(
                "qualification case {} has missing, unknown, or failed acceptance checks",
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
        if now.duration_since(finish)?.as_secs() > maximum_age {
            bail!("qualification evidence is expired");
        }
        if case.requirement_id == "rollout-observation"
            && (observation.observed_seconds < thresholds.soak_seconds
                || observation.operations.is_empty()
                || observation.operations.values().any(|count| *count == 0))
        {
            bail!("rollout observation lacks the required duration and operation denominators");
        }
    }
    Ok(())
}
