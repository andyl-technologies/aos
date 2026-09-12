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

use crate::artifact::{ArtifactKind, ArtifactRecord, ArtifactRelation};
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
    CONTRACT_V2, PackageExecution, QualificationMethod, QualificationPhase,
    QualificationRequirement, QualificationScope, QualificationTarget, TargetKind,
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
    /// Effective package criticality after runtime dependency inheritance.
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

/// Stable requirement identity for the closed native adapter matrix.
pub const NATIVE_ADAPTER_MATRIX_REQUIREMENT: &str = "ability-native-adapter-matrix";

/// Stable requirement identity for the native finalized-image rollout flight.
pub const NATIVE_IMAGE_ROLLOUT_REQUIREMENT: &str = "ability-native-image-rollout";

/// Canonical schema for an immutable native adapter matrix specification.
pub const NATIVE_ADAPTER_MATRIX_SPEC_V1: &str = "aos.qualification.native-adapter-matrix-spec/v1";

/// Canonical schema for observed native adapter matrix results.
pub const NATIVE_ADAPTER_MATRIX_OBSERVATION_V1: &str =
    "aos.release.native-adapter-matrix-observation/v1";

const NATIVE_ADAPTER_MATRIX_SCHEMA_V1: &str = "aos.qualification.native-adapter-matrix/v1";
const NATIVE_ADAPTER_MATRIX_SUBJECT_V1: &str = "aos.qualification.native-adapter-subject/v1";
const NATIVE_ADAPTER_SURFACE_V1: &str = "aos.qualification.native-adapter-surface/v1";
const NATIVE_ADAPTER_POSTCONDITION_PROBE_V2: &str =
    "aos.release.native-adapter-postcondition-probe/v2";
const NATIVE_ADAPTER_CELL_COHORT_SUBJECT_V1: &str =
    "aos.release.native-adapter-cell-cohort-subject/v1";
/// Canonical schema for a typed native adapter matrix execution environment.
pub const NATIVE_ADAPTER_MATRIX_ENVIRONMENT_V1: &str =
    "aos.release.native-adapter-matrix-environment/v1";
const NATIVE_ADAPTER_MATRIX_CHECK_PREFIX: &str = "native-adapter-matrix-v1-sha256-";
const NATIVE_ADAPTER_MATRIX_MAX_ADAPTERS: usize = 12;
const NATIVE_ADAPTER_MATRIX_MAX_METHODS: usize = 47;
const NATIVE_ADAPTER_MATRIX_MAX_SCENARIOS: usize = 28;
const NATIVE_ADAPTER_MATRIX_MAX_CELLS: usize =
    NATIVE_ADAPTER_MATRIX_MAX_METHODS * NATIVE_ADAPTER_MATRIX_MAX_SCENARIOS;
const NATIVE_ADAPTER_MAX_PROBE_FACTS: usize = 32;
const NATIVE_ADAPTER_MAX_PROBE_BYTES: usize = 64 * 1024;

/// One exact interface identity in the native adapter matrix subject.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterInterfaceIdentity {
    /// Stable public interface name.
    pub name: String,
    /// Public interface ABI version.
    pub abi: u32,
    /// Canonical interface document digest.
    pub descriptor: Sha256Digest,
}

/// Declared size bounds for one closed native adapter surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterSurfaceLimits {
    /// Exact number of adapters permitted by this surface revision.
    pub max_adapters: usize,
    /// Exact total number of adapter methods permitted by this surface revision.
    pub max_methods: usize,
    /// Exact number of scenarios permitted by this surface revision.
    pub max_scenarios: usize,
}

/// One method and its native recovery routes in an adapter surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterSurfaceMethod {
    /// Method used to cancel an in-flight effect, when supported.
    pub cancel: Option<String>,
    /// Whether the method observes or mutates external state.
    pub effect_class: String,
    /// Stable public method name.
    pub method: String,
    /// Method used to reconcile an indeterminate effect, when supported.
    pub reconcile: Option<String>,
}

/// One native adapter and its exact public interface surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterSurfaceAdapter {
    /// Stable native adapter identity.
    pub adapter: String,
    /// Public interface ABI version.
    pub interface_abi: u32,
    /// Canonical public interface document digest.
    pub interface_descriptor: Sha256Digest,
    /// Stable public interface name.
    pub interface_name: String,
    /// Sorted exact methods dispatched by this adapter.
    pub methods: Vec<NativeAdapterSurfaceMethod>,
    /// Native execution scope containing the adapter effects.
    pub scope: String,
}

/// One failure, recovery, or lifecycle scenario expanded across every method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterSurfaceScenario {
    /// Failure, recovery, or lifecycle boundary exercised by the scenario.
    pub boundary: String,
    /// Required candidate state.
    pub candidate: String,
    /// Injected or naturally observed failure classification.
    pub failure: String,
    /// Stable scenario identity used as the final cell-id component.
    pub id: String,
    /// Required predecessor state.
    pub predecessor: String,
}

/// Complete typed preimage from which a native adapter matrix is expanded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterSurfaceSpec {
    /// Sorted exact adapters covered by the matrix.
    pub adapters: Vec<NativeAdapterSurfaceAdapter>,
    /// Exact size declarations for this surface revision.
    pub limits: NativeAdapterSurfaceLimits,
    /// Matrix semantics used to expand this surface.
    pub matrix_schema: String,
    /// Ordered exact scenarios expanded across every method.
    pub scenarios: Vec<NativeAdapterSurfaceScenario>,
    /// Exact native adapter surface schema.
    pub schema: String,
    /// Subject semantics derived from this surface.
    pub subject_schema: String,
}

/// Complete native adapter surface committed by a matrix specification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterMatrixSubject {
    /// Exact subject schema.
    pub schema: String,
    /// Matrix semantics used to expand the subject.
    pub matrix_schema: String,
    /// Digest of the closed native adapter surface document.
    pub surface_digest: Sha256Digest,
    /// Number of distinct adapters in the surface.
    pub adapter_count: usize,
    /// Number of distinct adapter methods in the surface.
    pub method_count: usize,
    /// Number of failure and recovery scenarios per method.
    pub scenario_count: usize,
    /// Sorted exact interface identities in the surface.
    pub interfaces: Vec<NativeAdapterInterfaceIdentity>,
}

/// Native reconciliation and cancellation routes for one cell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterRecoverySpec {
    /// Method used to reconcile an indeterminate effect, when supported.
    pub reconcile: Option<String>,
    /// Method used to cancel an in-flight effect, when supported.
    pub cancel: Option<String>,
}

/// Immutable semantics of one native adapter qualification cell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterCellSpec {
    /// Globally unique cell identity.
    pub id: String,
    /// Matrix semantics used to construct the cell.
    pub matrix_schema: String,
    /// Native adapter implementation identity.
    pub adapter: String,
    /// Exact public interface identity dispatched by the adapter.
    pub interface: NativeAdapterInterfaceIdentity,
    /// Interface method exercised by the cell.
    pub method: String,
    /// Whether the method observes or mutates external state.
    pub effect_class: String,
    /// Native execution scope containing the effect.
    pub scope: String,
    /// Failure, recovery, or lifecycle boundary exercised by the cell.
    pub boundary: String,
    /// Injected or naturally observed failure classification.
    pub failure: String,
    /// Required predecessor state.
    pub predecessor: String,
    /// Required candidate state.
    pub candidate: String,
    /// Ordered acceptance conditions that determine the cell result.
    pub postconditions: Vec<String>,
    /// Native recovery routes available to the method.
    pub recovery: NativeAdapterRecoverySpec,
    /// Exact identity changes that invalidate this observation.
    pub invalidated_by: Vec<String>,
}

/// Complete immutable native adapter matrix committed by release policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterMatrixSpec {
    /// Exact matrix specification schema.
    pub schema: String,
    /// Full closed surface preimage from which the subject and cells are derived.
    pub surface: NativeAdapterSurfaceSpec,
    /// Closed adapter surface covered by every cell.
    pub subject: NativeAdapterMatrixSubject,
    /// Ordered complete cell specifications.
    pub cells: Vec<NativeAdapterCellSpec>,
}

/// Qualification state represented by a native adapter matrix environment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeAdapterMatrixEnvironmentStatus {
    /// The adapter retained explicit failure evidence without a production VM run.
    Unqualified,
    /// A production VM cohort supplied complete runtime identities.
    Production,
}

/// Immutable identity of one production matrix runtime component.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterMatrixComponentIdentity {
    /// Stable component name.
    pub name: String,
    /// Observed component version or release identity.
    pub version: String,
    /// Digest of the exact artifact or closure used by the cohort.
    pub digest: Sha256Digest,
}

/// Exact execution environment shared by every observed matrix cell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterMatrixEnvironment {
    /// Exact environment schema.
    pub schema_version: String,
    /// Whether this is an explicit unqualified result or a production VM run.
    pub status: NativeAdapterMatrixEnvironmentStatus,
    /// Platform that ran the matrix scenario.
    pub platform: Platform,
    /// Matrix specification executed by the scenario.
    pub spec_digest: Sha256Digest,
    /// Canonical scenario-registry identity that selected the harness closure.
    pub scenario_registry_digest: Sha256Digest,
    /// Candidate artifact-set identity copied from the qualification case.
    pub candidate_subjects_digest: Sha256Digest,
    /// Frozen predecessor manifest exercised by the scenario.
    pub predecessor_manifest_digest: Sha256Digest,
    /// Reason production evidence is unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unqualified_reason: Option<String>,
    /// Stable production cohort identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort: Option<String>,
    /// Exact QEMU closure used to host the cohort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu: Option<NativeAdapterMatrixComponentIdentity>,
    /// Exact VM firmware artifact used to boot each guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware: Option<NativeAdapterMatrixComponentIdentity>,
    /// Exact guest kernel artifact exercised by the cohort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_kernel: Option<NativeAdapterMatrixComponentIdentity>,
    /// Exact fault-injection tool closure used for boundaries and interruptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_injection_tool: Option<NativeAdapterMatrixComponentIdentity>,
    /// Exact scenario harness closure selected by the executor registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<NativeAdapterMatrixComponentIdentity>,
}

/// Observed postconditions for one exact native adapter matrix cell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterCellObservation {
    /// Cell identity copied from the immutable specification.
    pub id: String,
    /// Digest of the complete matching cell specification.
    pub cell_digest: Sha256Digest,
    /// Digest of the actual production execution environment.
    pub environment_digest: Sha256Digest,
    /// Canonical dynamic plan and author identity exercised by this cell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort_subject: Option<serde_json::Value>,
    /// Exact postcondition results; their conjunction determines cell success.
    pub postconditions: BTreeMap<String, CheckObservation>,
    /// Exact production probes for every passing postcondition.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub probes: BTreeMap<String, NativeAdapterPostconditionProbe>,
}

/// Retained production observation supporting one passing matrix postcondition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterPostconditionProbe {
    /// Exact postcondition probe schema.
    pub schema_version: String,
    /// Probe class required by the named postcondition.
    pub kind: String,
    /// Exact matrix cell identity exercised by this probe.
    pub cell_id: String,
    /// Digest of the immutable matrix cell exercised by this probe.
    pub cell_digest: Sha256Digest,
    /// Scenario-specific terminal or retained-state disposition.
    pub disposition: String,
    /// Candidate artifact population exercised by the probe.
    pub subject_digest: Sha256Digest,
    /// Canonical identity of the cell's retained dynamic cohort subject.
    pub cohort_subject_digest: Sha256Digest,
    /// Canonical identity of the retained observation preimage.
    pub observation_digest: Sha256Digest,
    /// Bounded structured facts observed independently of the adapter result.
    pub observations: BTreeMap<String, serde_json::Value>,
}

/// Exact cell binding around one cohort's dynamic production subject.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeAdapterCellCohortSubject {
    schema: String,
    cell_id: String,
    cell_digest: Sha256Digest,
    boundary: String,
    failure: String,
    candidate: String,
    predecessor: String,
    subject: serde_json::Value,
}

/// Complete observed results for an immutable native adapter matrix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterMatrixObservation {
    /// Exact observation schema.
    pub schema_version: String,
    /// Full immutable specification whose digest appears in release policy.
    pub spec: NativeAdapterMatrixSpec,
    /// Digest of the complete canonical specification.
    pub spec_digest: Sha256Digest,
    /// Typed execution environment whose digest appears in every cell.
    pub environment: NativeAdapterMatrixEnvironment,
    /// Ordered one-to-one cell observations.
    pub cells: Vec<NativeAdapterCellObservation>,
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
    /// Exact per-cell native adapter evidence, when this is the matrix case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_adapter_matrix: Option<NativeAdapterMatrixObservation>,
    /// Exact expanded case identity.
    pub case_digest: Sha256Digest,
    /// Canonical scenario-registry identity that binds immutable executable selection.
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
    let package_roles = inherited_package_roles(contract, manifest)?;
    let mut requirements: Vec<_> = contract
        .selected(&plan.registry, plan.release_class)?
        .filter(|gate| gate.phase == phase)
        .filter(|gate| {
            !qualification_snapshot
                || !matches!(
                    gate.id.as_str(),
                    "image-update-recovery" | NATIVE_IMAGE_ROLLOUT_REQUIREMENT
                )
        })
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
            let package_rule = if requirement.scope == QualificationScope::Packages {
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
                        })?,
                )
            } else {
                None
            };
            let predecessor = if requirement.id == "image-update-recovery"
                || requirement.id == NATIVE_ADAPTER_MATRIX_REQUIREMENT
                || requirement.id == NATIVE_IMAGE_ROLLOUT_REQUIREMENT
                || claim.as_ref().is_some_and(|claim| {
                    claim.minimum_assurance >= AssuranceLevel::A2
                        && claim
                            .requirements
                            .iter()
                            .any(|id| id == "image-update-recovery")
                })
                || package_rule.is_some_and(|rule| rule.execution.is_some())
            {
                Some(plan.qualification_predecessor.clone().ok_or_else(|| {
                    anyhow::anyhow!("qualification execution requires a frozen predecessor")
                })?)
            } else {
                None
            };
            let package_role = if let Some(rule) = package_rule {
                let direct = rule.role;
                let inherited = subjects
                    .iter()
                    .filter_map(|subject| package_roles.get(subject))
                    .copied()
                    .max()
                    .unwrap_or(direct);

                Some(direct.max(inherited))
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
                    Some(
                        contract
                            .thresholds_for(&plan.registry, plan.release_class)?
                            .soak_seconds,
                    )
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
                            let rule = contract
                                .package_rules
                                .iter()
                                .find(|rule| rule.name == package.name)
                                .ok_or_else(|| {
                                    anyhow::anyhow!("package lacks its criticality classification")
                                })?;
                            let mut subjects = artifact.artifact_ids.clone();
                            if let Some(PackageExecution::RecoveryImage { system_variant }) =
                                &rule.execution
                            {
                                let image = manifest
                                    .images
                                    .iter()
                                    .find(|image| image.system_variant == *system_variant)
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "package {} requires absent recovery image variant {}",
                                            package.name,
                                            system_variant
                                        )
                                    })?;
                                let image_cell = image
                                    .platforms
                                    .iter()
                                    .find(|image_cell| image_cell.platform == cell.platform)
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "package {} recovery image lacks platform {}",
                                            package.name,
                                            cell.platform
                                        )
                                    })?;
                                let MatrixCell::Artifact {
                                    artifact: image_artifact,
                                } = &image_cell.decision
                                else {
                                    bail!(
                                        "package {} recovery image platform is not an artifact",
                                        package.name
                                    );
                                };
                                subjects.extend(image_artifact.artifact_ids.iter().cloned());
                            }
                            add(
                                format!("{}/{}", package.name, cell.platform),
                                Some(cell.platform),
                                None,
                                subjects,
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

fn inherited_package_roles(
    contract: &crate::qualification::QualificationContract,
    manifest: &ReleaseManifestV1,
) -> Result<BTreeMap<String, crate::qualification::PackageRole>> {
    let artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let rules = contract
        .package_rules
        .iter()
        .map(|rule| (rule.name.as_str(), rule.role))
        .collect::<BTreeMap<_, _>>();
    let mut roles = BTreeMap::new();

    for package in &manifest.packages {
        let role = rules
            .get(package.name.as_str())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("package case lacks its criticality classification"))?;
        for cell in &package.platforms {
            let MatrixCell::Artifact { artifact } = &cell.decision else {
                continue;
            };
            propagate_package_role(&artifacts, &artifact.artifact_ids, role, &mut roles)?;
        }
    }

    Ok(roles)
}

fn propagate_package_role(
    artifacts: &BTreeMap<&str, &ArtifactRecord>,
    roots: &[String],
    role: crate::qualification::PackageRole,
    roles: &mut BTreeMap<String, crate::qualification::PackageRole>,
) -> Result<()> {
    let mut pending = roots.to_vec();

    while let Some(id) = pending.pop() {
        if roles.get(&id).is_some_and(|current| *current >= role) {
            continue;
        }
        let artifact = artifacts
            .get(id.as_str())
            .ok_or_else(|| anyhow::anyhow!("package closure references missing artifact {id}"))?;
        roles.insert(id, role);
        pending.extend(
            artifact
                .relationships
                .iter()
                .filter(|relationship| relationship.relation == ArtifactRelation::Contains)
                .map(|relationship| relationship.target.clone()),
        );
    }

    Ok(())
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
    let thresholds = contract.thresholds_for(&plan.registry, plan.release_class)?;
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
        let matrix_passed = validate_matrix_for_case(case, observation)?;
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
        if let Some(matrix_passed) = matrix_passed {
            passed &= matrix_passed;
        }
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

/// Validates exact per-cell results and derives whether the complete matrix passed.
///
/// The release case supplies the trusted specification digest through one
/// exact native-adapter-matrix acceptance-check token. The observation must
/// retain the full preimage and one result for every cell in the same order.
/// No aggregate status is trusted.
///
/// # Errors
///
/// Returns an error when the case is not the native adapter matrix case, the
/// policy token or specification is malformed, the frozen predecessor is
/// absent, the typed environment differs from the case or executor, a cell is
/// missing, duplicated, reordered, or changed, or postconditions are not exact
/// and documented. Every passing postcondition must retain a distinct,
/// subject-bound production probe with a valid canonical observation digest.
pub fn validate_native_adapter_matrix_observation(
    case: &QualificationCase,
    environment_digest: Sha256Digest,
    executor_digest: Sha256Digest,
    observation: &NativeAdapterMatrixObservation,
) -> Result<bool> {
    let expected_spec_digest = native_adapter_matrix_policy_digest(case)?;
    if case.predecessor.is_none() {
        bail!("native adapter matrix case lacks its frozen predecessor");
    }
    if observation.schema_version != NATIVE_ADAPTER_MATRIX_OBSERVATION_V1 {
        bail!("unsupported native adapter matrix observation schema");
    }

    validate_native_adapter_matrix_spec(&observation.spec)?;
    let actual_spec_digest = Sha256Digest::of_bytes(crate::canonical::to_vec(&observation.spec)?);
    if observation.spec_digest != actual_spec_digest || actual_spec_digest != expected_spec_digest {
        bail!("native adapter matrix specification differs from release policy");
    }
    let actual_environment_digest =
        Sha256Digest::of_bytes(crate::canonical::to_vec(&observation.environment)?);
    if actual_environment_digest != environment_digest {
        bail!("native adapter matrix environment differs from its observation identity");
    }
    validate_native_adapter_matrix_environment(case, executor_digest, observation)?;
    if observation.cells.len() != observation.spec.cells.len() {
        bail!("native adapter matrix result count differs from its specification");
    }

    let mut passed = true;
    let mut probe_digests = BTreeSet::new();
    for (spec, result) in observation.spec.cells.iter().zip(&observation.cells) {
        if result.id != spec.id {
            bail!("native adapter matrix cells are missing, extra, duplicated, or reordered");
        }
        let expected_cell_digest = Sha256Digest::of_bytes(crate::canonical::to_vec(spec)?);
        if result.cell_digest != expected_cell_digest {
            bail!("native adapter matrix cell differs from its committed specification");
        }
        if result.environment_digest != environment_digest {
            bail!("native adapter matrix cell differs from its execution environment");
        }
        let expected_postconditions = spec
            .postconditions
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let actual_postconditions = result
            .postconditions
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if actual_postconditions != expected_postconditions
            || result
                .postconditions
                .values()
                .any(|postcondition| postcondition.detail.trim().is_empty())
        {
            bail!("native adapter matrix cell postconditions are not exact and documented");
        }
        let passing_postconditions = result
            .postconditions
            .iter()
            .filter_map(|(name, result)| result.passed.then_some(name.as_str()))
            .collect::<BTreeSet<_>>();
        let probe_names = result
            .probes
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if probe_names != passing_postconditions {
            bail!("native adapter matrix passing postconditions lack exact production probes");
        }
        let cohort_subject_digest = match &result.cohort_subject {
            Some(subject) if !passing_postconditions.is_empty() && subject.is_object() => {
                let subject_bytes = crate::canonical::to_vec(subject)?;
                if subject_bytes.len() > NATIVE_ADAPTER_MAX_PROBE_BYTES {
                    bail!("native adapter matrix cohort subject exceeds its size bound");
                }
                validate_native_adapter_cell_cohort_subject(spec, expected_cell_digest, subject)?;
                Some(Sha256Digest::of_bytes(subject_bytes))
            }
            None if passing_postconditions.is_empty() => None,
            _ => bail!("native adapter matrix cohort subject differs from cell success"),
        };
        if observation.environment.status == NativeAdapterMatrixEnvironmentStatus::Unqualified
            && !passing_postconditions.is_empty()
        {
            bail!("unqualified native adapter matrix cells cannot carry passing postconditions");
        }

        for (postcondition, probe) in &result.probes {
            let cohort_subject_digest = cohort_subject_digest.ok_or_else(|| {
                anyhow::anyhow!("native adapter matrix probe lacks its cohort subject")
            })?;
            validate_native_adapter_postcondition_probe(
                case,
                spec,
                postcondition,
                cohort_subject_digest,
                expected_cell_digest,
                probe,
            )?;
            if !probe_digests.insert(probe.observation_digest) {
                bail!(
                    "native adapter matrix replays a production probe across postconditions or cells"
                );
            }
        }
        passed &= passing_postconditions.len() == result.postconditions.len();
    }

    if passed && observation.environment.status == NativeAdapterMatrixEnvironmentStatus::Unqualified
    {
        bail!("an unqualified native adapter matrix environment cannot pass");
    }

    Ok(passed)
}

fn validate_native_adapter_postcondition_probe(
    case: &QualificationCase,
    cell: &NativeAdapterCellSpec,
    postcondition: &str,
    cohort_subject_digest: Sha256Digest,
    cell_digest: Sha256Digest,
    probe: &NativeAdapterPostconditionProbe,
) -> Result<()> {
    let expected_kind = native_adapter_postcondition_probe_kind(postcondition)
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix postcondition has no probe class"))?;
    let expected_disposition = native_adapter_expected_disposition(cell)
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix scenario has no disposition"))?;
    if probe.schema_version != NATIVE_ADAPTER_POSTCONDITION_PROBE_V2
        || probe.kind != expected_kind
        || probe.cell_id != cell.id
        || probe.cell_digest != cell_digest
        || probe.disposition != expected_disposition
        || probe.subject_digest != case.subjects_digest
        || probe.cohort_subject_digest != cohort_subject_digest
        || probe.observations.is_empty()
        || probe.observations.len() > NATIVE_ADAPTER_MAX_PROBE_FACTS
        || probe
            .observations
            .iter()
            .any(|(name, value)| !matrix_token(name) || value.is_null())
    {
        bail!("native adapter matrix postcondition probe is malformed or misbound");
    }

    let observation_bytes = crate::canonical::to_vec(&probe.observations)?;
    if observation_bytes.len() > NATIVE_ADAPTER_MAX_PROBE_BYTES
        || Sha256Digest::of_bytes(observation_bytes) != probe.observation_digest
    {
        bail!("native adapter matrix postcondition probe digest is invalid");
    }
    Ok(())
}

fn validate_native_adapter_cell_cohort_subject(
    cell: &NativeAdapterCellSpec,
    cell_digest: Sha256Digest,
    subject: &serde_json::Value,
) -> Result<()> {
    let binding: NativeAdapterCellCohortSubject = serde_json::from_value(subject.clone())?;
    if binding.schema != NATIVE_ADAPTER_CELL_COHORT_SUBJECT_V1
        || binding.cell_id != cell.id
        || binding.cell_digest != cell_digest
        || binding.boundary != cell.boundary
        || binding.failure != cell.failure
        || binding.candidate != cell.candidate
        || binding.predecessor != cell.predecessor
        || !binding.subject.is_object()
    {
        bail!("native adapter matrix cohort subject is bound to another cell");
    }
    Ok(())
}

/// Returns the required scenario disposition for one immutable matrix cell.
#[must_use]
pub fn native_adapter_expected_disposition(cell: &NativeAdapterCellSpec) -> Option<&'static str> {
    let scenario = cell.id.rsplit('/').next()?;
    match scenario {
        "interrupt-before-acquisition" => Some("rejected-before-acquisition"),
        "interrupt-after-acquisition" => Some("unsettled-after-acquisition"),
        "interrupt-after-durable-intent" => Some("reconciled-after-interruption"),
        "lose-external-result" => Some("reconciled-completed"),
        "interrupt-after-durable-outcome" => Some("completed-before-interruption"),
        "cancel-unsettled-attempt" if cell.recovery.cancel.is_none() => {
            Some("unsupported-cancellation-retains-ownership")
        }
        "cancel-unsettled-attempt" => Some("cancelled-after-reconciliation"),
        "expire-attempt-deadline" => Some("deadline-exceeded-retains-ownership"),
        "fail-cleanup" => Some("cleanup-failed-retains-ownership"),
        "fail-release" => Some("release-failed-retains-ownership"),
        "revoke-caller-before-acquisition"
        | "revoke-caller-after-acquisition"
        | "revoke-caller-before-external-effect"
        | "revoke-provider-before-acquisition"
        | "revoke-provider-after-acquisition"
        | "revoke-provider-before-external-effect"
        | "revoke-enforcement-before-acquisition"
        | "revoke-enforcement-after-acquisition"
        | "revoke-enforcement-before-external-effect"
        | "revoke-assignment-before-acquisition"
        | "revoke-assignment-after-acquisition"
        | "revoke-assignment-before-external-effect" => Some("rejected-before-effect"),
        "replace-executor-incarnation" => Some("stale-executor-rejected"),
        "replace-provider-incarnation" => Some("stale-provider-rejected"),
        "adopt-compatible-state" => Some("compatible-state-adopted"),
        "reject-unsupported-transfer" => Some("transfer-rejected-before-effect"),
        "activate-retained-target" => Some("retained-target-activated"),
        "block-dependent-effect" => Some("dependent-effect-blocked"),
        "reject-foreign-resource-mutation" => Some("foreign-mutation-rejected"),
        _ => None,
    }
}

fn native_adapter_postcondition_probe_kind(postcondition: &str) -> Option<&'static str> {
    match postcondition {
        "durable-attempt-state-classified" => Some("journal-timeline"),
        "at-most-one-resource-owner" => Some("ownership-inventory"),
        "foreign-resources-unchanged" => Some("foreign-resource-snapshot"),
        "dependent-effects-not-executed" => Some("dependency-barrier"),
        "fresh-receiving-authority" => Some("authority-incarnation"),
        "compatible-state-adopted" => Some("state-adoption"),
        "exactly-one-resource-owner" => Some("exact-ownership-inventory"),
        "transfer-rejected-before-candidate-effect" => Some("transfer-rejection"),
        "predecessor-remains-sole-owner" => Some("predecessor-ownership"),
        "current-grants-reauthorized" => Some("authority-grants"),
        "retained-target-identity-preserved" => Some("target-identity"),
        "prerequisite-failure-recorded" => Some("prerequisite-failure"),
        "foreign-attempt-rejected-before-mutation" => Some("foreign-attempt-rejection"),
        _ => None,
    }
}

/// Constructs the deterministic aggregate check derived from exact matrix cells.
///
/// # Errors
///
/// Returns an error if the cell or postcondition count cannot be represented.
pub fn native_adapter_matrix_check(
    observation: &NativeAdapterMatrixObservation,
    passed: bool,
) -> Result<CheckObservation> {
    let passed_cells = observation
        .cells
        .iter()
        .filter(|cell| cell.postconditions.values().all(|result| result.passed))
        .count();
    let postcondition_count = observation
        .cells
        .iter()
        .try_fold(0_usize, |count, cell| {
            count.checked_add(cell.postconditions.len())
        })
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix postcondition count overflows"))?;
    Ok(CheckObservation {
        passed,
        detail: format!(
            "derived {passed_cells}/{} native adapter cells and {postcondition_count} exact postconditions",
            observation.cells.len()
        ),
    })
}

/// Validates the complete matrix-specific portion of one case observation.
///
/// Returns the derived matrix result, or `None` for a non-matrix case. Matrix
/// checks and operation denominators are recomputed from the exact cell results.
///
/// # Errors
///
/// Returns an error for inapplicable matrix evidence or when any specification,
/// environment, cell, aggregate check, or operation denominator is inconsistent.
pub fn validate_matrix_for_case(
    case: &QualificationCase,
    observation: &QualificationObservation,
) -> Result<Option<bool>> {
    if case.requirement_id != NATIVE_ADAPTER_MATRIX_REQUIREMENT {
        if observation.native_adapter_matrix.is_some() {
            bail!("native adapter matrix evidence is inapplicable to this qualification case");
        }
        return Ok(None);
    }

    let matrix = observation.native_adapter_matrix.as_ref().ok_or_else(|| {
        anyhow::anyhow!("native adapter matrix case lacks exact per-cell evidence")
    })?;
    let passed = validate_native_adapter_matrix_observation(
        case,
        observation.environment_digest,
        observation.executor_digest,
        matrix,
    )?;
    let matrix_check = case
        .checks
        .iter()
        .find(|name| name.starts_with(NATIVE_ADAPTER_MATRIX_CHECK_PREFIX))
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix case lacks its policy check"))?;
    let check = observation
        .checks
        .get(matrix_check)
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix case lacks its derived check"))?;
    let expected_check = native_adapter_matrix_check(matrix, passed)?;
    if check != &expected_check {
        bail!("native adapter matrix aggregate check differs from its derived result");
    }

    let cell_count = u64::try_from(matrix.cells.len())?;
    let postcondition_count = matrix.cells.iter().try_fold(0_u64, |count, cell| {
        Ok::<_, std::num::TryFromIntError>(count + u64::try_from(cell.postconditions.len())?)
    })?;
    let mut expected_operation_names = case
        .measurements
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    expected_operation_names.insert("matrix_cells_reported");
    expected_operation_names.insert("matrix_postconditions_reported");
    let actual_operation_names = observation
        .operations
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_operation_names != expected_operation_names
        || observation.operations.get("matrix_cells_reported") != Some(&cell_count)
        || observation.operations.get("matrix_postconditions_reported")
            != Some(&postcondition_count)
    {
        bail!("native adapter matrix execution denominators differ from its cell results");
    }

    Ok(Some(passed))
}

fn native_adapter_matrix_policy_digest(case: &QualificationCase) -> Result<Sha256Digest> {
    if case.requirement_id != NATIVE_ADAPTER_MATRIX_REQUIREMENT {
        bail!("native adapter matrix case lacks one exact policy check");
    }

    let mut matrix_checks = case
        .checks
        .iter()
        .filter_map(|check| check.strip_prefix(NATIVE_ADAPTER_MATRIX_CHECK_PREFIX));
    let encoded = matrix_checks.next().ok_or_else(|| {
        anyhow::anyhow!("native adapter matrix case lacks one exact policy check")
    })?;
    if matrix_checks.next().is_some() {
        bail!("native adapter matrix case has multiple policy checks");
    }
    Sha256Digest::parse(&format!("sha256:{encoded}"))
}

fn validate_native_adapter_matrix_environment(
    case: &QualificationCase,
    executor_digest: Sha256Digest,
    observation: &NativeAdapterMatrixObservation,
) -> Result<()> {
    let environment = &observation.environment;
    let predecessor = case.predecessor.as_ref().ok_or_else(|| {
        anyhow::anyhow!("native adapter matrix case lacks its frozen predecessor")
    })?;
    if environment.schema_version != NATIVE_ADAPTER_MATRIX_ENVIRONMENT_V1
        || environment.platform != Platform::X86_64Linux
        || environment.spec_digest != observation.spec_digest
        || environment.scenario_registry_digest != executor_digest
        || environment.candidate_subjects_digest != case.subjects_digest
        || environment.predecessor_manifest_digest != predecessor.manifest_digest
    {
        bail!("native adapter matrix environment differs from its case identities");
    }

    let production_components = [
        environment.qemu.as_ref(),
        environment.firmware.as_ref(),
        environment.guest_kernel.as_ref(),
        environment.fault_injection_tool.as_ref(),
        environment.harness.as_ref(),
    ];
    match environment.status {
        NativeAdapterMatrixEnvironmentStatus::Unqualified => {
            if environment
                .unqualified_reason
                .as_ref()
                .is_none_or(|reason| reason.trim().is_empty())
                || environment.cohort.is_some()
                || production_components
                    .iter()
                    .any(|component| component.is_some())
            {
                bail!("unqualified native adapter matrix environment has production identities");
            }
        }
        NativeAdapterMatrixEnvironmentStatus::Production => {
            if environment.unqualified_reason.is_some()
                || environment
                    .cohort
                    .as_ref()
                    .is_none_or(|cohort| !matrix_token(cohort))
                || production_components.iter().any(|component| {
                    component.is_none_or(|component| {
                        !matrix_token(&component.name)
                            || !matrix_component_version(&component.version)
                    })
                })
            {
                bail!("production native adapter matrix environment is incomplete");
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_native_adapter_matrix_spec(spec: &NativeAdapterMatrixSpec) -> Result<()> {
    if spec.schema != NATIVE_ADAPTER_MATRIX_SPEC_V1 {
        bail!("native adapter matrix specification has an unsupported schema");
    }

    let (expected_subject, expected_cells) = expand_native_adapter_surface(&spec.surface)?;
    if spec.subject != expected_subject {
        bail!("native adapter matrix subject differs from its surface preimage");
    }
    if spec.cells != expected_cells {
        bail!("native adapter matrix cells differ from their deterministic surface expansion");
    }

    Ok(())
}

fn expand_native_adapter_surface(
    surface: &NativeAdapterSurfaceSpec,
) -> Result<(NativeAdapterMatrixSubject, Vec<NativeAdapterCellSpec>)> {
    if surface.schema != NATIVE_ADAPTER_SURFACE_V1
        || surface.matrix_schema != NATIVE_ADAPTER_MATRIX_SCHEMA_V1
        || surface.subject_schema != NATIVE_ADAPTER_MATRIX_SUBJECT_V1
        || surface.adapters.is_empty()
        || surface.adapters.len() > NATIVE_ADAPTER_MATRIX_MAX_ADAPTERS
        || surface.scenarios.is_empty()
        || surface.scenarios.len() > NATIVE_ADAPTER_MATRIX_MAX_SCENARIOS
        || !strictly_sorted_by(&surface.adapters, |adapter| adapter.adapter.clone())
        || !unique_by(&surface.adapters, |adapter| adapter.interface_name.clone())
        || !unique_by(&surface.scenarios, |scenario| scenario.id.clone())
    {
        bail!("native adapter matrix surface has inconsistent schemas, bounds, or ordering");
    }

    let mut method_count = 0_usize;
    for adapter in &surface.adapters {
        if !valid_native_adapter(adapter) {
            bail!("native adapter matrix surface contains an invalid adapter");
        }
        method_count = method_count
            .checked_add(adapter.methods.len())
            .ok_or_else(|| anyhow::anyhow!("native adapter matrix method count overflows"))?;
    }
    if method_count == 0 || method_count > NATIVE_ADAPTER_MATRIX_MAX_METHODS {
        bail!("native adapter matrix surface method count is outside v1 bounds");
    }
    if surface.scenarios.iter().any(|scenario| {
        !matrix_token(&scenario.id)
            || !matrix_token(&scenario.boundary)
            || !matrix_token(&scenario.failure)
            || !matrix_token(&scenario.predecessor)
            || !matrix_token(&scenario.candidate)
            || ![
                "after-acquisition",
                "after-durable-intent",
                "after-durable-outcome",
                "after-external-return",
                "before-acquisition",
                "before-external-effect",
                "cancellation",
                "cleanup",
                "deadline",
                "foreign-resource",
                "prerequisite",
                "recovery",
                "release",
                "retained-target-activation",
            ]
            .contains(&scenario.boundary.as_str())
    }) {
        bail!("native adapter matrix surface contains an invalid scenario");
    }
    if surface.limits.max_adapters != surface.adapters.len()
        || surface.limits.max_methods != method_count
        || surface.limits.max_scenarios != surface.scenarios.len()
    {
        bail!("native adapter matrix surface limits differ from its exact population");
    }

    let surface_digest = Sha256Digest::of_bytes(crate::canonical::to_vec(surface)?);
    let mut interfaces = surface
        .adapters
        .iter()
        .map(|adapter| NativeAdapterInterfaceIdentity {
            name: adapter.interface_name.clone(),
            abi: adapter.interface_abi,
            descriptor: adapter.interface_descriptor,
        })
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    let subject = NativeAdapterMatrixSubject {
        schema: surface.subject_schema.clone(),
        matrix_schema: surface.matrix_schema.clone(),
        surface_digest,
        adapter_count: surface.adapters.len(),
        method_count,
        scenario_count: surface.scenarios.len(),
        interfaces,
    };

    let cell_count = method_count
        .checked_mul(surface.scenarios.len())
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix cell count overflows"))?;
    if cell_count > NATIVE_ADAPTER_MATRIX_MAX_CELLS {
        bail!("native adapter matrix cell count is outside v1 bounds");
    }
    let mut cells = Vec::with_capacity(cell_count);
    for adapter in &surface.adapters {
        for method in &adapter.methods {
            for scenario in &surface.scenarios {
                cells.push(expand_native_adapter_cell(
                    surface, adapter, method, scenario,
                ));
            }
        }
    }
    cells.sort_by(|left, right| left.id.cmp(&right.id));

    Ok((subject, cells))
}

fn valid_native_adapter(adapter: &NativeAdapterSurfaceAdapter) -> bool {
    if !matrix_token(&adapter.adapter)
        || !matrix_token(&adapter.interface_name)
        || adapter.interface_abi != 1
        || ![
            "bootstrap-manager",
            "host-filesystem",
            "host-manager",
            "host-machine",
            "host-process",
            "host-resource",
            "kubernetes-cluster",
        ]
        .contains(&adapter.scope.as_str())
        || adapter.methods.is_empty()
        || !strictly_sorted_by(&adapter.methods, |method| method.method.clone())
    {
        return false;
    }

    let method_names = adapter
        .methods
        .iter()
        .map(|method| method.method.as_str())
        .collect::<BTreeSet<_>>();
    adapter.methods.iter().all(|method| {
        matrix_token(&method.method)
            && ["mutation", "observation"].contains(&method.effect_class.as_str())
            && [method.reconcile.as_deref(), method.cancel.as_deref()]
                .into_iter()
                .flatten()
                .all(|route| matrix_token(route) && method_names.contains(route))
    })
}

fn expand_native_adapter_cell(
    surface: &NativeAdapterSurfaceSpec,
    adapter: &NativeAdapterSurfaceAdapter,
    method: &NativeAdapterSurfaceMethod,
    scenario: &NativeAdapterSurfaceScenario,
) -> NativeAdapterCellSpec {
    let failure = if scenario.failure == "route-dependent" {
        if method.cancel.is_some() {
            "cancelled-after-reconciliation"
        } else {
            "unsupported-cancellation-retains-ownership"
        }
    } else {
        &scenario.failure
    };

    NativeAdapterCellSpec {
        id: format!(
            "{}/{}/abi-{}/{}/{}",
            adapter.adapter,
            adapter.interface_name,
            adapter.interface_abi,
            method.method,
            scenario.id
        ),
        matrix_schema: surface.matrix_schema.clone(),
        adapter: adapter.adapter.clone(),
        interface: NativeAdapterInterfaceIdentity {
            name: adapter.interface_name.clone(),
            abi: adapter.interface_abi,
            descriptor: adapter.interface_descriptor,
        },
        method: method.method.clone(),
        effect_class: method.effect_class.clone(),
        scope: adapter.scope.clone(),
        boundary: scenario.boundary.clone(),
        failure: failure.to_owned(),
        predecessor: scenario.predecessor.clone(),
        candidate: scenario.candidate.clone(),
        postconditions: native_adapter_postconditions(scenario),
        recovery: NativeAdapterRecoverySpec {
            reconcile: method.reconcile.clone(),
            cancel: method.cancel.clone(),
        },
        invalidated_by: ["subject", "policy", "executor", "environment"]
            .map(str::to_owned)
            .to_vec(),
    }
}

fn native_adapter_postconditions(scenario: &NativeAdapterSurfaceScenario) -> Vec<String> {
    let mut postconditions = [
        "durable-attempt-state-classified",
        "at-most-one-resource-owner",
        "foreign-resources-unchanged",
    ]
    .map(str::to_owned)
    .to_vec();
    if scenario.failure != "none" {
        postconditions.push("dependent-effects-not-executed".into());
    }
    match scenario.id.as_str() {
        "adopt-compatible-state" => postconditions.extend(
            [
                "fresh-receiving-authority",
                "compatible-state-adopted",
                "exactly-one-resource-owner",
            ]
            .map(str::to_owned),
        ),
        "reject-unsupported-transfer" => postconditions.extend(
            [
                "fresh-receiving-authority",
                "transfer-rejected-before-candidate-effect",
                "predecessor-remains-sole-owner",
            ]
            .map(str::to_owned),
        ),
        "activate-retained-target" => postconditions.extend(
            [
                "current-grants-reauthorized",
                "retained-target-identity-preserved",
                "exactly-one-resource-owner",
            ]
            .map(str::to_owned),
        ),
        "block-dependent-effect" => {
            postconditions.push("prerequisite-failure-recorded".into());
        }
        "reject-foreign-resource-mutation" => {
            postconditions.push("foreign-attempt-rejected-before-mutation".into());
        }
        _ => {}
    }
    postconditions
}

fn matrix_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
}

fn matrix_component_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'_' | b'-'))
}

fn unique_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(key(value)))
}

fn strictly_sorted_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
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
