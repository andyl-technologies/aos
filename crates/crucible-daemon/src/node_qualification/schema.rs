//! Defines the closed behavioral claim ledger and independent resource ceilings.
//!
//! ```text
//! ClaimV1 = exact-unit | classes | catalog | applicability-policy | requirements
//! Requirement = RFC-ID | disposition | original-cases | trusted-NA-reason
//! ```

use std::collections::BTreeSet;

use crucible_node_contract::{ContentRef, Validate};
use serde::{Deserialize, Serialize};

/// Selects one orthogonal qualification class without implying another axis.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationClass {
    /// Covers identity, admission, lifecycle, errors and ownership.
    BaseProvider,
    /// Covers actual exact stop and publication coordinates.
    ExactTiming,
    /// Covers windows, physical budgets and logical boundary publication.
    QuantizedTiming,
    /// Covers equivalent trajectories under identical admitted inputs.
    Repeatable,
    /// Covers only the enumerated architectural and device state.
    CaptureArchitectural,
    /// Covers complete modeled continuation requiring retained live resources.
    CaptureModeledLive,
    /// Covers complete modeled continuation after original source retirement.
    CaptureModeledDurable,
    /// Covers isolation of independently running continuations.
    BranchIsolated,
    /// Covers response replay under authenticated original applicability.
    ConditionalReplay,
    /// Covers the exact semantic role/port profiles in the qualification unit.
    RoleProfile,
}

/// Binds the complete independently measured qualification unit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationUnit {
    /// Binds executables, adapters, patches, model and dependency closure.
    pub implementation: ContentRef,
    /// Binds actual owners, CPU/devices, parameters, seeds and operating modes.
    pub realization: ContentRef,
    /// Binds the complete immutable node descriptor inventory.
    pub descriptors: ContentRef,
    /// Binds selected timing, state, visibility and operation contracts.
    pub contracts: ContentRef,
    /// Binds selected semantic ports, features and role specifications.
    pub port_profiles: ContentRef,
    /// Binds required ISA, ABI, kernel, threading and resource constraints.
    pub environment: ContentRef,
    /// Binds actual independent harness executable and revision.
    pub harness: ContentRef,
    /// Binds all workload, fixture, reference and oracle source identities.
    pub fixtures: ContentRef,
    /// Binds the exact complete normative specification interpreted by policy.
    pub specification: ContentRef,
}

impl QualificationUnit {
    pub(super) fn references(&self) -> [&ContentRef; 9] {
        [
            &self.implementation,
            &self.realization,
            &self.descriptors,
            &self.contracts,
            &self.port_profiles,
            &self.environment,
            &self.harness,
            &self.fixtures,
            &self.specification,
        ]
    }

    pub(super) fn validate(&self) -> Result<(), QualificationError> {
        for reference in self.references() {
            reference.validate()?;
        }
        Ok(())
    }
}

/// Identifies how a case actually obtained its observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    /// Uses original measurements against the realized native provider.
    RealizedProvider,
    /// Exercises a real endpoint through an independent public protocol peer.
    IndependentProtocol,
    /// Exercises a model or test double, granting no native class by itself.
    Model,
    /// Inspects source against the explicitly stated obligation.
    SourceInspection,
}

/// Retains every original case result, including failures and omissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseVerdict {
    /// Satisfies the declared independent oracle.
    Passed,
    /// Violates the oracle or leaves an unresolved native outcome.
    Failed,
    /// Never executes, including dependent cases blocked by an earlier failure.
    NotExecuted,
    /// Cannot exercise the promised feature in this configuration.
    Unsupported,
}

/// Retains one original case and the authenticated oracle/result closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEvidence {
    /// Names the original case without replacing IDs on retries.
    pub case: String,
    /// Identifies the observation mechanism without upgrading model results.
    pub kind: CaseKind,
    /// Retains the original verdict without filtering failed populations.
    pub verdict: CaseVerdict,
    /// Enumerates only classes independently covered by this actual case.
    pub classes: BTreeSet<QualificationClass>,
    /// Binds the complete original case result and difficult-state observations.
    pub result: ContentRef,
    /// Binds the independent oracle and its exact expected property.
    pub oracle: ContentRef,
}

/// Classifies the complete disposition of one RFC obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementDisposition {
    /// Has authenticated successful cases or independent inspection evidence.
    Passed,
    /// Has an unresolved failed obligation.
    Failed,
    /// Is unsupported in a claimed applicable class.
    Unsupported,
    /// Is applicable but has not been exercised or inspected.
    NotExecuted,
    /// Is excluded by exact independently trusted applicability policy.
    NotApplicable,
}

/// Retains coverage or an exact trusted exclusion for one normative obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementResult {
    /// Names one exact source-owned RFC-0025 requirement ID.
    pub requirement: String,
    /// Keeps success, failure, omissions and nonapplicability distinct.
    pub disposition: RequirementDisposition,
    /// Retains every original case, including nonpassing results.
    pub cases: Vec<CaseEvidence>,
    /// States the exact installed-policy rationale for a nonapplicable row.
    pub not_applicable_reason: Option<String>,
}

/// Describes one complete behavioral claim without conferring acceptance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationClaim {
    /// Identifies this independent format, `crucible.node-qualification`.
    pub format: String,
    /// Selects closed claim edition one.
    pub version: u16,
    /// Binds the complete independently authenticated configuration tuple.
    pub unit: QualificationUnit,
    /// Enumerates the exact orthogonal classes claimed by this evidence.
    pub classes: BTreeSet<QualificationClass>,
    /// Binds the compiled complete normative requirement ID inventory.
    pub catalog: ContentRef,
    /// Binds independently installed applicability and exclusion policy.
    pub applicability_policy: ContentRef,
    /// Retains every normative requirement once in strictly increasing order.
    pub requirements: Vec<RequirementResult>,
    /// Retains a prior immutable claim without rewriting its original results.
    pub supersedes: Option<ContentRef>,
    /// Binds known exclusions, expiry conditions and difficult-state coverage.
    pub limitations: ContentRef,
}

/// Bounds claim parsing, coverage traversal and evidence verification.
#[derive(Clone, Copy, Debug)]
pub struct QualificationLimits {
    /// Bounds the complete canonical claim before parsing or cloning it.
    pub maximum_claim_bytes: usize,
    /// Bounds all original cases before evidence callbacks execute.
    pub maximum_cases: usize,
    /// Bounds distinct references and queued dependency traversal before fetch.
    pub maximum_evidence_objects: usize,
    /// Bounds each evidence object for streaming trusted verification.
    pub maximum_evidence_bytes: u64,
    /// Bounds the distinct complete referenced evidence closure.
    pub maximum_total_evidence_bytes: u64,
}

impl Default for QualificationLimits {
    fn default() -> Self {
        Self {
            maximum_claim_bytes: 4 * 1024 * 1024,
            maximum_cases: 16_384,
            maximum_evidence_objects: 65_536,
            maximum_evidence_bytes: 512 * 1024 * 1024,
            maximum_total_evidence_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

/// Reports malformed, unavailable, untrusted or out-of-scope qualification.
#[derive(Debug, thiserror::Error)]
pub enum QualificationError {
    /// The closed portable record or content reference is invalid.
    #[error(transparent)]
    Contract(#[from] crucible_node_contract::ContractError),
    /// The exact qualification gate refuses without granting native authority.
    #[error("qualification refused: {0}")]
    Refused(&'static str),
    /// Installed evidence authentication rejects the claim or original case.
    #[error("qualification evidence unavailable or rejected: {0}")]
    Evidence(String),
}
