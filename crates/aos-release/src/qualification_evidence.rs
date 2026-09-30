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

use std::collections::BTreeMap;

use anyhow::{Result, bail};
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
pub const QUALIFICATION_CASE: &str = "aos.release.qualification-case/v1";

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
