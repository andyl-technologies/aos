//! Exact subject expansion and observations for shared release qualification.
//!
//! An observation names a canonical case digest. Cases bind the phase,
//! requirement, artifact population, target configuration, and predecessor.
//! Reports for a fixture, another platform, or a different phase cannot satisfy
//! a release case even when they reuse the same human-readable gate name.
//!
//! ```text
//! destination -> profile + change scope + soak -> requirements + claims
//! case -> requirement + target + subjects + predecessor
//! observation -> case digest + checks + environment + executor + measurements
//! ```
//!
//! [`cases`] expands the obligations of one planned destination at one hold
//! point; [`assess_observations`] and [`validate_observations`] judge signed
//! evidence against exactly those cases.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use aos_ability_model::OptionType;
use aos_ability_plan::module_graph::Lifetime;
use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;
use crate::platform::Platform;
use crate::qualification::claims::{
    CompatibilityAssessment, MeasurementRequirement, QualificationClaim,
};
use crate::qualification::environment::EnvironmentInventory;
use crate::qualification::{QualificationMethod, QualificationPhase, QualificationTarget};

mod assessment;
mod expansion;
mod selection;

pub use assessment::{assess_observations, validate_observations};
pub use expansion::cases;

/// Schema and digest domain of one expanded qualification case.
pub const QUALIFICATION_CASE: &str = "aos.release.qualification-case/v2";

#[cfg(test)]
#[path = "qualification_k3s_tests.rs"]
mod k3s_tests;

#[cfg(test)]
#[path = "qualification_evidence/tests.rs"]
mod tests;

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
    /// Exact case schema identifier.
    pub schema_version: String,
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
    /// Exact evaluated matrix copied verbatim from the selected requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_operation_spec: Option<NativeOperationQualificationSpec>,
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
    /// Returns an error for an unsupported case schema or failed canonical
    /// encoding.
    pub fn digest(&self) -> Result<Sha256Digest> {
        if self.schema_version != QUALIFICATION_CASE {
            bail!("unsupported qualification case schema");
        }
        Sha256Digest::of_canonical(QUALIFICATION_CASE, self)
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

/// Canonical schema for an immutable native adapter matrix specification.
pub const NATIVE_ADAPTER_MATRIX_SPEC: &str = "aos.qualification.native-operation-matrix-spec";

/// Canonical schema for the exact production applicability partition.
pub const NATIVE_ADAPTER_MATRIX_APPLICABILITY: &str =
    "aos.qualification.native-operation-matrix-applicability";

/// Canonical schema for observed native adapter matrix results.
pub const NATIVE_ADAPTER_MATRIX_OBSERVATION_V1: &str =
    "aos.release.native-adapter-matrix-observation/v1";

const NATIVE_ADAPTER_MATRIX_SCHEMA: &str = "aos.qualification.native-operation-matrix";
const NATIVE_ADAPTER_SURFACE: &str = "aos.qualification.native-operation-matrix-surface";
const NATIVE_ADAPTER_POSTCONDITION_PROBE_V1: &str =
    "aos.release.native-adapter-postcondition-probe/v1";
const NATIVE_ADAPTER_CELL_COHORT_SUBJECT_V1: &str =
    "aos.release.native-adapter-cell-cohort-subject/v1";
/// Canonical schema for a typed native adapter matrix execution environment.
pub const NATIVE_ADAPTER_MATRIX_ENVIRONMENT_V1: &str =
    "aos.release.native-adapter-matrix-environment/v1";
pub const NATIVE_ADAPTER_MATRIX_CHECK: &str = "native-adapter-matrix";
const NATIVE_ADAPTER_MATRIX_MAX_ADAPTERS: usize = 128;
const NATIVE_ADAPTER_MATRIX_MAX_SCENARIOS: usize = 256;
const NATIVE_ADAPTER_MATRIX_MAX_CELLS: usize = 1_048_576;
const NATIVE_ADAPTER_MAX_PROBE_FACTS: usize = 32;
const NATIVE_ADAPTER_MAX_PROBE_BYTES: usize = 64 * 1024;

/// Identifies one operation in the merged native ability declarations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationIdentity {
    /// Names the ability owning the operation.
    pub ability: String,
    /// Names the operation within that ability.
    pub name: String,
}

/// Retains the actual native input and result option types.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationDeclaration {
    /// Names the ability owning the operation.
    pub ability: String,
    /// Names the operation within that ability.
    pub name: String,
    /// Projects the operation's merged argument options.
    pub input_type: OptionType,
    /// Projects the operation's merged result options.
    pub result_type: OptionType,
}

/// Selects one terminal native handler protocol command.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeOperationAction {
    /// Establishes or updates the exact requested state.
    Apply,
    /// Releases state owned by the exact retained invocation.
    Remove,
}

impl NativeOperationAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Remove => "remove",
        }
    }
}

/// Retains the exact executable selected by native handler evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeOperationHandler {
    /// Dispatches a source-built executable in one retained artifact.
    Process {
        /// Names the immutable artifact containing the executable.
        artifact: String,
        /// Names the exact executable inside that artifact.
        executable: String,
    },
}

/// Records one configured native effect without exposing its argument values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationEffect {
    /// Contains the logical identity hash used by the checked graph.
    pub id: String,
    /// Retains the installation scope, owner, and operation instance identity.
    pub identity: Vec<String>,
    /// Binds the checked desired value and handler interpretation.
    pub revision: String,
    /// Preserves the configured reuse and teardown lifetime.
    pub lifetime: Lifetime,
    /// Names the checked prerequisites of the configured effect.
    pub dependencies: Vec<String>,
}

/// Records concrete effect lifetimes and explicit backend state-format evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationStateContract {
    /// Lists the configured effect lifetimes in canonical order.
    pub resource_lifetimes: Vec<Lifetime>,
    /// Names an authenticated backend state format when one is explicitly known.
    pub state_format: Option<Sha256Digest>,
}

/// Binds a merged operation to its selected native handler and configured effects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterSurfaceAdapter {
    /// Names this exact operation and selected handler group.
    pub adapter: String,
    /// Records scenario families that this subject must qualify.
    pub conformance_families: Vec<String>,
    /// Retains the merged native operation declaration.
    pub operation: NativeOperationDeclaration,
    /// Retains the selected executable artifact and path.
    pub handler: NativeOperationHandler,
    /// Lists configured effects in logical identity hash order.
    pub effects: Vec<NativeOperationEffect>,
    /// Lists the native handler commands covered by this subject.
    pub actions: Vec<NativeOperationAction>,
    /// Retains the native installation scope containing these effects.
    pub scope: Vec<String>,
    /// Records concrete lifetimes and explicit backend state-format evidence.
    pub state_contract: NativeOperationStateContract,
}

/// One failure, recovery, or lifecycle scenario expanded across native actions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterSurfaceScenario {
    /// Configured lifetime and state-format predicates that select applicable cells.
    pub applicability: NativeAdapterScenarioApplicability,
    /// Failure, recovery, or lifecycle boundary exercised by the scenario.
    pub boundary: String,
    /// Required candidate state.
    pub candidate: String,
    /// Declares how the executor derives the expected terminal disposition.
    pub disposition: NativeAdapterDispositionPolicy,
    /// Injected or naturally observed failure classification.
    pub failure: String,
    /// Conformance family that selects this scenario for an implementation.
    pub family: String,
    /// Stable scenario identity used as the final cell-id component.
    pub id: String,
    /// Ordered acceptance conditions and their evidence record kinds.
    pub postconditions: Vec<NativeAdapterPostconditionPolicy>,
    /// Required predecessor state.
    pub predecessor: String,
}

/// Declares the configured lifetimes and state-format evidence required by a scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterScenarioApplicability {
    /// Native actions supported by this scenario; an empty list permits both.
    pub required_actions: Vec<NativeOperationAction>,
    /// Effect lifetimes that must occur in the selected native operation group.
    pub required_resource_lifetimes: Vec<Lifetime>,
    /// Whether the implementation must authenticate a state-format descriptor.
    pub requires_state_format: bool,
}

/// Selects how a scenario's expected terminal disposition is obtained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeAdapterDispositionPolicy {
    /// Requires one exact policy-authored disposition.
    Exact {
        /// Names the exact terminal disposition.
        value: String,
    },
    /// Selects one of two policy-authored results from the checked cancel route.
    CancellationRoute {
        /// Required disposition when the checked operation supports cancellation.
        supported: String,
        /// Required disposition when the checked operation has no cancel route.
        unsupported: String,
    },
}

/// One implementation-independent acceptance condition selected by scenario policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterPostconditionPolicy {
    /// Evidence record kind expected from an executable qualification cohort.
    pub evidence_kind: String,
    /// Stable acceptance-condition name exposed in matrix observations.
    pub name: String,
}

/// Complete typed preimage from which a native adapter matrix is expanded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterSurfaceSpec {
    /// Sorted exact adapters covered by the matrix.
    pub adapters: Vec<NativeAdapterSurfaceAdapter>,
    /// Closed registry of conformance families used by the scenario policy.
    pub families: Vec<String>,
    /// Exact identity dimensions that invalidate retained observations.
    pub invalidation_dimensions: Vec<String>,
    /// Matrix semantics used to expand this surface.
    pub matrix_schema: String,
    /// Ordered exact scenarios expanded across every native action.
    pub scenarios: Vec<NativeAdapterSurfaceScenario>,
    /// Exact native adapter surface schema.
    pub schema: String,
}

/// Selects one scenario without conflating identical names in different families.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationScenarioIdentity {
    /// Names the policy family containing this scenario.
    pub family: String,
    /// Names the exact scenario within that family.
    pub id: String,
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
    /// Identifies the merged native operation selected for this cell.
    pub operation: NativeOperationIdentity,
    /// Selects the actual native handler command exercised by the cell.
    pub action: NativeOperationAction,
    /// Selects the exact policy scenario and its conformance family.
    pub scenario: NativeOperationScenarioIdentity,
    /// Native execution scope containing the effect.
    pub scope: Vec<String>,
    /// Failure, recovery, or lifecycle boundary exercised by the cell.
    pub boundary: String,
    /// Injected or naturally observed failure classification.
    pub failure: String,
    /// Required predecessor state.
    pub predecessor: String,
    /// Required candidate state.
    pub candidate: String,
    /// Declares how the executor derives the expected terminal disposition.
    pub disposition: NativeAdapterDispositionPolicy,
    /// Lifetime and state-format predicates copied from the selected scenario.
    pub applicability: NativeAdapterScenarioApplicability,
    /// Ordered acceptance conditions that determine the cell result.
    pub postconditions: Vec<String>,
    /// Maps each acceptance condition to its policy-selected evidence kind.
    pub postcondition_kinds: BTreeMap<String, String>,
    /// Exact identity changes that invalidate this observation.
    pub invalidated_by: Vec<String>,
}

/// One matrix cell excluded by its configured lifetime or state-format constraints.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterInapplicableCell {
    /// Exact cell identity from the complete Cartesian matrix.
    pub cell_id: String,
    /// Stable lifetime or state-format reason for the exclusion.
    pub reason: String,
}

/// Fail-closed partition of complete matrix cells by production applicability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterMatrixApplicability {
    /// Exact applicability schema.
    pub schema: String,
    /// Ordered exact cells that require production VM evidence.
    pub applicable_cell_ids: Vec<String>,
    /// Ordered exact cells whose native operation facts make the scenario inapplicable.
    pub inapplicable_cells: Vec<NativeAdapterInapplicableCell>,
}

/// Complete immutable native adapter matrix committed by release policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterMatrixSpec {
    /// Ordered semantic operations selected from the authenticated candidate graph.
    ///
    /// Composition operations select their terminal descendants. Graph custody
    /// validators check that expansion; this document retains its exact policy.
    pub required_operations: Vec<NativeOperationIdentity>,
    /// Exact matrix specification schema.
    pub schema: String,
    /// Full closed surface preimage selected by the Nix policy evaluator.
    pub surface: NativeAdapterSurfaceSpec,
    /// Ordered complete cell specifications.
    pub cells: Vec<NativeAdapterCellSpec>,
    /// Exact partition that identifies production-applicable cells.
    pub applicability: NativeAdapterMatrixApplicability,
}

/// Source role of a case-selected immutable evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeEvaluationRole {
    /// The evaluation captured from the signed candidate image baseline.
    CandidateBaseline,
    /// A locked evaluation derived from the baseline and case-owned sources.
    Scenario,
}

/// Exact immutable evaluation and ordered scenario source custody.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSelectedEvaluation {
    /// Distinguishes boot baseline custody from a case-authored scenario.
    pub role: NativeEvaluationRole,
    /// Names the retained immutable deployment bundle.
    pub locator: String,
    /// Retains ordered immutable scenario module locators, excluding baseline sources.
    pub scenario_sources: Vec<String>,
}

/// Closed independently evaluated operation cohort selected by release policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationCohortSpec {
    /// Names the cohort independently of its cell identities.
    pub id: String,
    /// Retains the complete candidate-specific operation matrix.
    pub matrix_spec: NativeAdapterMatrixSpec,
    /// Commits the exact baseline or scenario source evaluation.
    pub selected_evaluation: NativeSelectedEvaluation,
    /// Commits the admitted fixture baseline applied before the selected flight.
    pub adoption_evaluation: NativeSelectedEvaluation,
}

/// Authored semantic coverage over independently admitted native cohorts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationQualificationSpec {
    /// Identifies the native operation qualification specification.
    pub schema: String,
    /// Lists the semantic operations that must be covered by checked cohorts.
    pub required_operations: Vec<NativeOperationIdentity>,
    /// Lists independently checked closed matrices in cohort identity order.
    pub cohorts: Vec<NativeOperationCohortSpec>,
}

/// Checked evidence for one exact authored cohort.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationCohortObservation {
    /// Names the authored cohort whose cells were exercised.
    pub id: String,
    /// Retains the exact authored matrix, without a cross-cohort graph union.
    pub matrix_spec: NativeAdapterMatrixSpec,
    /// Retains the exact authored source selection.
    pub selected_evaluation: NativeSelectedEvaluation,
    /// Commits the admitted fixture baseline applied before the selected flight.
    pub adoption_evaluation: NativeSelectedEvaluation,
    /// Commits canonical bytes of the independently checked matrix.
    pub spec_digest: Sha256Digest,
    /// Commits candidate bytes authenticated against case-selected artifact evidence.
    ///
    /// The executor checks captured bytes and source admissions before reporting;
    /// this digest does not by itself authorize a self-claimed candidate.
    pub candidate_digest: Sha256Digest,
    /// Commits independently authenticated baseline bundle bytes before adoption.
    pub adoption_digest: Sha256Digest,
    /// Contains exactly one observation per applicable cell in this cohort.
    pub cells: Vec<NativeAdapterCellObservation>,
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
    /// Canonical dynamic execution subject exercised by this cell.
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
    /// Typed execution environment whose digest appears in every cell.
    pub environment: NativeAdapterMatrixEnvironment,
    /// Ordered one-to-one observations for every production-applicable cell.
    pub cohorts: Vec<NativeOperationCohortObservation>,
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
/// Validates exact per-cell results and derives whether the complete matrix passed.
///
/// The release case carries the exact evaluated specification. The observation
/// binds its digest and retains one result for every applicable cell in the same
/// order. No aggregate status is trusted.
///
/// # Errors
///
/// Returns an error when the case is not the native adapter matrix case, the
/// case specification is absent or malformed, the frozen predecessor is
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
    let qualification = native_operation_spec_for_case(case)?;
    validate_native_operation_qualification_spec(qualification)?;
    if case.predecessor.is_none() {
        bail!("native adapter matrix case lacks its frozen predecessor");
    }
    if observation.schema_version != NATIVE_ADAPTER_MATRIX_OBSERVATION_V1 {
        bail!("unsupported native adapter matrix observation schema");
    }

    let actual_environment_digest =
        Sha256Digest::of_bytes(crate::canonical::to_vec(&observation.environment)?);
    if actual_environment_digest != environment_digest {
        bail!("native adapter matrix environment differs from its observation identity");
    }
    validate_native_adapter_matrix_environment(case, executor_digest, observation)?;
    if observation.cohorts.len() != qualification.cohorts.len() {
        bail!("native cohort evidence differs from its authored population");
    }

    let mut passed = true;
    for (authored, observed) in qualification.cohorts.iter().zip(&observation.cohorts) {
        if observed.id != authored.id
            || observed.matrix_spec != authored.matrix_spec
            || observed.selected_evaluation != authored.selected_evaluation
            || observed.adoption_evaluation != authored.adoption_evaluation
            || observed.spec_digest
                != Sha256Digest::of_bytes(crate::canonical::to_vec(&authored.matrix_spec)?)
        {
            bail!("native cohort evidence differs from its exact authored context");
        }
        passed &= validate_native_cohort_cells(
            case,
            environment_digest,
            &authored.matrix_spec,
            &observed.cells,
            observation.environment.status,
        )?;
    }
    Ok(passed)
}

fn validate_native_cohort_cells(
    case: &QualificationCase,
    environment_digest: Sha256Digest,
    spec: &NativeAdapterMatrixSpec,
    cells: &[NativeAdapterCellObservation],
    status: NativeAdapterMatrixEnvironmentStatus,
) -> Result<bool> {
    let applicable_cells = native_adapter_applicable_cells(spec);
    if cells.len() != applicable_cells.len() {
        bail!("native adapter matrix result count differs from its specification");
    }

    let mut passed = true;
    let mut probe_digests = BTreeSet::new();
    for (spec, result) in applicable_cells.into_iter().zip(cells) {
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
        if status == NativeAdapterMatrixEnvironmentStatus::Unqualified
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

    if passed && status == NativeAdapterMatrixEnvironmentStatus::Unqualified {
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
    let expected_kind = cell
        .postcondition_kinds
        .get(postcondition)
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix postcondition has no probe class"))?;
    let valid_disposition = match &cell.disposition {
        NativeAdapterDispositionPolicy::Exact { value } => probe.disposition == *value,
        NativeAdapterDispositionPolicy::CancellationRoute {
            supported,
            unsupported,
        } => probe.disposition == *supported || probe.disposition == *unsupported,
    };
    if probe.schema_version != NATIVE_ADAPTER_POSTCONDITION_PROBE_V1
        || probe.kind != *expected_kind
        || probe.cell_id != cell.id
        || probe.cell_digest != cell_digest
        || !valid_disposition
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
pub fn native_adapter_expected_disposition(cell: &NativeAdapterCellSpec) -> Option<&str> {
    match &cell.disposition {
        NativeAdapterDispositionPolicy::Exact { value } => Some(value),
        NativeAdapterDispositionPolicy::CancellationRoute { .. } => None,
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
        .cohorts
        .iter()
        .flat_map(|cohort| &cohort.cells)
        .filter(|cell| cell.postconditions.values().all(|result| result.passed))
        .count();
    let postcondition_count = observation
        .cohorts
        .iter()
        .flat_map(|cohort| &cohort.cells)
        .try_fold(0_usize, |count, cell| {
            count.checked_add(cell.postconditions.len())
        })
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix postcondition count overflows"))?;
    Ok(CheckObservation {
        passed,
        detail: format!(
            "derived {passed_cells}/{} native adapter cells and {postcondition_count} exact postconditions",
            observation
                .cohorts
                .iter()
                .map(|cohort| cohort.cells.len())
                .sum::<usize>()
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
        .find(|name| name.as_str() == NATIVE_ADAPTER_MATRIX_CHECK)
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix case lacks its policy check"))?;
    let check = observation
        .checks
        .get(matrix_check)
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix case lacks its derived check"))?;
    let expected_check = native_adapter_matrix_check(matrix, passed)?;
    if check != &expected_check {
        bail!("native adapter matrix aggregate check differs from its derived result");
    }

    let cell_count = u64::try_from(
        matrix
            .cohorts
            .iter()
            .map(|cohort| cohort.cells.len())
            .sum::<usize>(),
    )?;
    let postcondition_count = matrix
        .cohorts
        .iter()
        .flat_map(|cohort| &cohort.cells)
        .try_fold(0_u64, |count, cell| {
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

fn native_operation_spec_for_case(
    case: &QualificationCase,
) -> Result<&NativeOperationQualificationSpec> {
    if case.requirement_id != NATIVE_ADAPTER_MATRIX_REQUIREMENT {
        bail!("native adapter matrix case has the wrong requirement identity");
    }
    if case
        .checks
        .iter()
        .filter(|check| check.as_str() == NATIVE_ADAPTER_MATRIX_CHECK)
        .count()
        != 1
    {
        bail!("native adapter matrix case lacks its stable acceptance check");
    }
    case.native_operation_spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("native adapter matrix case lacks its exact specification"))
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

fn valid_evaluation_selection(evaluation: &NativeSelectedEvaluation) -> bool {
    immutable_source_locator(&evaluation.locator)
        && evaluation.scenario_sources.len() <= 4096
        && unique_by(&evaluation.scenario_sources, Clone::clone)
        && evaluation
            .scenario_sources
            .iter()
            .all(|path| immutable_source_locator(path))
        && match evaluation.role {
            NativeEvaluationRole::CandidateBaseline => evaluation.scenario_sources.is_empty(),
            NativeEvaluationRole::Scenario => !evaluation.scenario_sources.is_empty(),
        }
}

/// Validates independently authored cohort custody and required semantic coverage.
///
/// # Errors
/// Returns an error for malformed source locators, duplicate cohorts, matrix
/// drift, or a semantic operation absent from all selected cohort policies.
pub fn validate_native_operation_qualification_spec(
    spec: &NativeOperationQualificationSpec,
) -> Result<()> {
    if spec.schema != "aos.qualification.native-operation-spec"
        || spec.cohorts.is_empty()
        || spec.cohorts.len() > 4096
        || !strictly_sorted_by(&spec.cohorts, |cohort| cohort.id.clone())
        || !valid_required_operations(&spec.required_operations)
    {
        bail!("native operation qualification specification is malformed");
    }
    let mut selected = BTreeSet::new();
    for cohort in &spec.cohorts {
        validate_native_adapter_matrix_spec(&cohort.matrix_spec)?;
        if !matrix_token(&cohort.id)
            || !valid_evaluation_selection(&cohort.selected_evaluation)
            || !valid_evaluation_selection(&cohort.adoption_evaluation)
        {
            bail!("native cohort source custody is malformed");
        }
        selected.extend(
            cohort
                .matrix_spec
                .required_operations
                .iter()
                .map(|operation| (&operation.ability, &operation.name)),
        );
    }
    if spec
        .required_operations
        .iter()
        .any(|operation| !selected.contains(&(&operation.ability, &operation.name)))
    {
        bail!("required native semantic operation lacks an independently selected cohort");
    }
    Ok(())
}

fn immutable_source_locator(path: &str) -> bool {
    path.len() <= 4096
        && path.starts_with("/nix/store/")
        && !path.contains('\0')
        && !path
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        && path.len() > "/nix/store/".len()
}

fn valid_required_operations(operations: &[NativeOperationIdentity]) -> bool {
    !operations.is_empty()
        && operations.len() <= NATIVE_ADAPTER_MATRIX_MAX_ADAPTERS
        && strictly_sorted_by(operations, |operation| {
            (operation.ability.clone(), operation.name.clone())
        })
        && operations.iter().all(|operation| {
            [&operation.ability, &operation.name].iter().all(|value| {
                value.len() <= 96
                    && value
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphabetic)
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
        })
}

/// Validates native operation subjects, exact scenario cells, and applicability.
///
/// # Errors
/// Returns an error for malformed declarations, inconsistent selected handlers,
/// forged effect identities, cell drift, or an incomplete applicability partition.
pub fn validate_native_adapter_matrix_spec(spec: &NativeAdapterMatrixSpec) -> Result<()> {
    if spec.schema != NATIVE_ADAPTER_MATRIX_SPEC {
        bail!("native adapter matrix specification has an unsupported schema");
    }

    if !valid_required_operations(&spec.required_operations) {
        bail!("native matrix required operations are empty, malformed, or unordered");
    }

    let surface = &spec.surface;
    if surface.schema != NATIVE_ADAPTER_SURFACE
        || surface.matrix_schema != NATIVE_ADAPTER_MATRIX_SCHEMA
        || surface.adapters.is_empty()
        || surface.adapters.len() > NATIVE_ADAPTER_MATRIX_MAX_ADAPTERS
        || surface.scenarios.is_empty()
        || surface.scenarios.len() > NATIVE_ADAPTER_MATRIX_MAX_SCENARIOS
        || !strictly_sorted_by(&surface.adapters, |adapter| adapter.adapter.clone())
        || surface.families.is_empty()
        || !unique_by(&surface.families, |family| family.clone())
        || surface.families.iter().any(|family| !matrix_token(family))
        || surface.invalidation_dimensions.is_empty()
        || !unique_by(&surface.invalidation_dimensions, |dimension| {
            dimension.clone()
        })
        || surface
            .invalidation_dimensions
            .iter()
            .any(|dimension| !matrix_token(dimension))
        || !unique_by(&surface.scenarios, |scenario| {
            (scenario.family.clone(), scenario.id.clone())
        })
    {
        bail!("native adapter matrix surface has inconsistent schemas or ordering");
    }

    for adapter in &surface.adapters {
        if !valid_native_adapter(adapter)
            || adapter
                .conformance_families
                .iter()
                .any(|family| !surface.families.contains(family))
        {
            bail!("native adapter matrix surface contains an invalid adapter");
        }
    }
    for scenario in &surface.scenarios {
        if !matrix_token(&scenario.id)
            || !matrix_token(&scenario.boundary)
            || !matrix_token(&scenario.failure)
            || !matrix_token(&scenario.family)
            || !surface.families.contains(&scenario.family)
            || !matrix_token(&scenario.predecessor)
            || !matrix_token(&scenario.candidate)
            || scenario.postconditions.is_empty()
            || !unique_by(&scenario.postconditions, |postcondition| {
                postcondition.name.clone()
            })
            || scenario.postconditions.iter().any(|postcondition| {
                !matrix_token(&postcondition.name) || !matrix_token(&postcondition.evidence_kind)
            })
            || scenario
                .applicability
                .required_actions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || scenario
                .applicability
                .required_resource_lifetimes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || match &scenario.disposition {
                NativeAdapterDispositionPolicy::Exact { value } => !matrix_token(value),
                NativeAdapterDispositionPolicy::CancellationRoute {
                    supported,
                    unsupported,
                } => {
                    !matrix_token(supported)
                        || !matrix_token(unsupported)
                        || supported == unsupported
                }
            }
        {
            bail!("native adapter matrix surface contains an invalid scenario");
        }
    }

    if spec.cells.is_empty()
        || spec.cells.len() > NATIVE_ADAPTER_MATRIX_MAX_CELLS
        || !strictly_sorted_by(&spec.cells, |cell| cell.id.clone())
    {
        bail!("native adapter matrix cells are empty, oversized, or unordered");
    }
    for cell in &spec.cells {
        let adapter = surface
            .adapters
            .iter()
            .find(|adapter| adapter.adapter == cell.adapter)
            .ok_or_else(|| anyhow::anyhow!("native adapter cell references an absent adapter"))?;
        if !adapter.actions.contains(&cell.action) {
            bail!("native operation cell references an absent handler action");
        }
        let scenario = surface
            .scenarios
            .iter()
            .find(|scenario| {
                scenario.id == cell.scenario.id && scenario.family == cell.scenario.family
            })
            .ok_or_else(|| anyhow::anyhow!("native adapter cell references an absent scenario"))?;
        let expected_id = format!(
            "{}/{}/{}/{}/{}/{}",
            adapter.adapter,
            adapter.operation.ability,
            adapter.operation.name,
            cell.action.as_str(),
            scenario.family,
            scenario.id
        );
        let expected_postconditions = scenario
            .postconditions
            .iter()
            .map(|postcondition| postcondition.name.clone())
            .collect::<Vec<_>>();
        let expected_postcondition_kinds = scenario
            .postconditions
            .iter()
            .map(|postcondition| {
                (
                    postcondition.name.clone(),
                    postcondition.evidence_kind.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if cell.id != expected_id
            || cell.matrix_schema != surface.matrix_schema
            || cell.operation.ability != adapter.operation.ability
            || cell.operation.name != adapter.operation.name
            || cell.scope != adapter.scope
            || cell.boundary != scenario.boundary
            || cell.failure != scenario.failure
            || cell.predecessor != scenario.predecessor
            || cell.candidate != scenario.candidate
            || cell.disposition != scenario.disposition
            || cell.applicability != scenario.applicability
            || cell.postconditions != expected_postconditions
            || cell.postcondition_kinds != expected_postcondition_kinds
            || cell.invalidated_by != surface.invalidation_dimensions
        {
            bail!("native adapter cell differs from its referenced declarations");
        }
    }

    let applicability = &spec.applicability;
    let applicable_ids = applicability
        .applicable_cell_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let inapplicable_ids = applicability
        .inapplicable_cells
        .iter()
        .map(|entry| entry.cell_id.as_str())
        .collect::<BTreeSet<_>>();
    let cell_ids = spec
        .cells
        .iter()
        .map(|cell| cell.id.as_str())
        .collect::<BTreeSet<_>>();
    let partition = applicable_ids
        .union(&inapplicable_ids)
        .copied()
        .collect::<BTreeSet<_>>();
    if applicability.schema != NATIVE_ADAPTER_MATRIX_APPLICABILITY
        || applicability.applicable_cell_ids.is_empty()
        || !strictly_sorted_by(&applicability.applicable_cell_ids, Clone::clone)
        || applicability.applicable_cell_ids.len() != applicable_ids.len()
        || applicability.inapplicable_cells.len() != inapplicable_ids.len()
        || applicability
            .inapplicable_cells
            .windows(2)
            .any(|pair| pair[0].cell_id >= pair[1].cell_id)
        || applicability.inapplicable_cells.iter().any(|entry| {
            !matches!(
                entry.reason.as_str(),
                "required-resource-lifetime-unavailable"
                    | "missing-authenticated-state-format"
                    | "unsupported-scenario-action"
            )
        })
        || !applicable_ids.is_disjoint(&inapplicable_ids)
        || partition != cell_ids
    {
        bail!("native adapter applicability is not an exact cell partition");
    }

    for cell in &spec.cells {
        let action_supported = cell.applicability.required_actions.is_empty()
            || cell.applicability.required_actions.contains(&cell.action);
        let exclusion = applicability
            .inapplicable_cells
            .iter()
            .find(|entry| entry.cell_id == cell.id);
        if (!action_supported
            && exclusion.map(|entry| entry.reason.as_str()) != Some("unsupported-scenario-action"))
            || (action_supported
                && exclusion.is_some_and(|entry| entry.reason == "unsupported-scenario-action"))
        {
            bail!("native scenario action applicability contradicts its authored action predicate");
        }
    }

    Ok(())
}

/// Returns the ordered production-applicable cells from a validated matrix spec.
pub fn native_adapter_applicable_cells(
    spec: &NativeAdapterMatrixSpec,
) -> Vec<&NativeAdapterCellSpec> {
    let applicable = spec
        .applicability
        .applicable_cell_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    spec.cells
        .iter()
        .filter(|cell| applicable.contains(cell.id.as_str()))
        .collect()
}

fn valid_native_adapter(adapter: &NativeAdapterSurfaceAdapter) -> bool {
    let NativeOperationHandler::Process {
        artifact,
        executable,
    } = &adapter.handler;
    let expected_lifetimes = adapter
        .effects
        .iter()
        .map(|effect| effect.lifetime)
        .collect::<BTreeSet<_>>();
    let declared_lifetimes = adapter
        .state_contract
        .resource_lifetimes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    matrix_token(&adapter.adapter)
        && native_identity_part(&adapter.operation.ability)
        && native_identity_part(&adapter.operation.name)
        && !adapter.conformance_families.is_empty()
        && unique_by(&adapter.conformance_families, Clone::clone)
        && adapter.scope.iter().all(|part| native_identity_part(part))
        && artifact.starts_with("/nix/store/")
        && artifact.len() <= 4096
        && !artifact.contains(['\n', '\0'])
        && executable.starts_with(&format!("{artifact}/"))
        && executable.len() <= 4096
        && !executable.split('/').any(|part| matches!(part, "." | ".."))
        && !adapter.effects.is_empty()
        && strictly_sorted_by(&adapter.effects, |effect| effect.id.clone())
        && adapter
            .effects
            .iter()
            .all(|effect| valid_native_effect(adapter, effect))
        && !adapter.actions.is_empty()
        && strictly_sorted_by(&adapter.actions, |action| *action)
        && adapter
            .state_contract
            .resource_lifetimes
            .windows(2)
            .all(|pair| native_lifetime_name(pair[0]) < native_lifetime_name(pair[1]))
        && expected_lifetimes == declared_lifetimes
}

fn valid_native_effect(
    adapter: &NativeAdapterSurfaceAdapter,
    effect: &NativeOperationEffect,
) -> bool {
    let expected_length = adapter.scope.len() + 4;
    if effect.identity.len() != expected_length
        || effect.identity[..adapter.scope.len()] != adapter.scope
        || effect.identity[expected_length - 3] != adapter.operation.ability
        || effect.identity[expected_length - 2] != adapter.operation.name
        || effect
            .identity
            .iter()
            .any(|part| !native_identity_part(part))
        || !native_graph_hash(&effect.id)
        || !native_graph_hash(&effect.revision)
        || effect.dependencies.iter().any(|id| !native_graph_hash(id))
        || !strictly_sorted_by(&effect.dependencies, Clone::clone)
    {
        return false;
    }

    let Ok(identity_bytes) = crate::canonical::to_vec(&effect.identity) else {
        return false;
    };
    Sha256Digest::of_bytes(identity_bytes).to_string() == format!("sha256:{}", effect.id)
}

fn native_lifetime_name(lifetime: Lifetime) -> &'static str {
    match lifetime {
        Lifetime::Instance => "instance",
        Lifetime::Persistent => "persistent",
        Lifetime::Transaction => "transaction",
    }
}

fn native_identity_part(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.contains('\0')
}

fn native_graph_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
