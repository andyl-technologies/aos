//! Shared command-exit policy over a validated immutable assessment.
//!
//! Report policy selects automation failure independently from command execution,
//! reviewed dispositions and release eligibility. No condition grants authority
//! or removes a raw vulnerability claim.
//!
//! ```json
//! {"schema":"aos.assessment-report-policy/v1",
//!  "conditions":["coverage","updates","vulnerabilities"]}
//! ```

use anyhow::{Result, ensure};
use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::{Deserialize, Serialize};

use crate::input::Profile;
use crate::result::{PackageAssessmentV1, VersionDecision};
use crate::security::CoverageState;
use crate::validation::decode_with_limits;

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 16_384,
    max_depth: 8,
    max_items: 128,
    max_string_bytes: 128,
};

/// Selects a conservative automation failure condition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportFailureCondition {
    /// Fails when requested assessment coverage is incomplete or unknown.
    Coverage,
    /// Fails for an actionable maintained-stream update; waiting/manual/frozen
    /// candidates alone do not satisfy this condition.
    Updates,
    /// Fails for any raw applicable, potentially applicable or unresolved
    /// vulnerability claim, independently from reviewed dispositions.
    Vulnerabilities,
}

/// Retains the normalized nonempty condition set for one report invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentReportPolicyV1 {
    /// Exact command-policy discriminator.
    pub schema: String,
    /// Distinct conditions in canonical enum order.
    pub conditions: Vec<ReportFailureCondition>,
}

impl AssessmentReportPolicyV1 {
    /// Normalizes repeated caller selections into one explicit finite policy.
    ///
    /// # Errors
    /// Returns an error when no condition is selected.
    pub fn new(mut conditions: Vec<ReportFailureCondition>) -> Result<Self> {
        conditions.sort();
        conditions.dedup();
        let policy = Self {
            schema: "aos.assessment-report-policy/v1".into(),
            conditions,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Decodes a closed normalized command policy.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, unknown/null fields, invalid schema,
    /// excessive bounds, duplicates, empty conditions or noncanonical ordering.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let policy: Self = decode_with_limits(bytes, "assessment report policy", LIMITS)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Checks that every requested failure condition has an evaluated profile.
    ///
    /// Callers run this before admitting a scan or acquiring source evidence.
    ///
    /// # Errors
    /// Returns an error for invalid policy or missing update/vulnerability scope.
    pub fn validate_profiles(&self, profiles: &[Profile]) -> Result<()> {
        self.validate()?;
        for condition in &self.conditions {
            let required = match condition {
                ReportFailureCondition::Coverage => None,
                ReportFailureCondition::Updates => Some(Profile::Updates),
                ReportFailureCondition::Vulnerabilities => Some(Profile::Vulnerabilities),
            };
            ensure!(
                required.is_none_or(|profile| profiles.contains(&profile)),
                "report failure condition requires its assessment profile"
            );
        }
        ensure!(
            !profiles.is_empty(),
            "report policy requires an evaluated profile"
        );
        Ok(())
    }

    /// Evaluates the same deterministic report outcome for local and Hub clients.
    ///
    /// # Errors
    /// Returns an error for invalid policy/result or an unevaluated condition.
    pub fn evaluate(
        &self,
        assessment: &PackageAssessmentV1,
    ) -> Result<AssessmentReportPolicyOutcomeV1> {
        self.validate()?;
        assessment.validate()?;
        for subject in &assessment.subject_results {
            let profiles = subject
                .coverage
                .iter()
                .map(|coverage| coverage.profile)
                .collect::<Vec<_>>();
            self.validate_profiles(&profiles)?;
        }
        let matched_conditions = self
            .conditions
            .iter()
            .copied()
            .filter(|condition| match condition {
                ReportFailureCondition::Coverage => assessment.coverage != CoverageState::Complete,
                ReportFailureCondition::Updates => {
                    assessment.subject_results.iter().any(|subject| {
                        subject
                            .versions
                            .iter()
                            .any(|version| version.decision == VersionDecision::UpdateAvailable)
                    })
                }
                ReportFailureCondition::Vulnerabilities => assessment
                    .subject_results
                    .iter()
                    .any(|subject| !subject.findings.is_empty()),
            })
            .collect::<Vec<_>>();
        Ok(AssessmentReportPolicyOutcomeV1 {
            schema: "aos.assessment-report-policy-outcome/v1".into(),
            assessment_digest: assessment.digest()?,
            policy: self.clone(),
            failed: !matched_conditions.is_empty(),
            matched_conditions,
        })
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-report-policy/v1"
                && !self.conditions.is_empty()
                && self.conditions.len() <= 3
                && self.conditions.windows(2).all(|pair| pair[0] < pair[1]),
            "invalid normalized assessment report policy"
        );
        Ok(())
    }
}

/// Binds normalized command policy and its result to one exact assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentReportPolicyOutcomeV1 {
    /// Exact outcome discriminator.
    pub schema: String,
    /// Exact immutable assessment evaluated by this invocation.
    pub assessment_digest: Sha256Digest,
    /// Complete normalized policy rather than an uninspectable threshold.
    pub policy: AssessmentReportPolicyV1,
    /// True exactly when at least one selected condition matched.
    pub failed: bool,
    /// Matched conditions in normalized policy order.
    pub matched_conditions: Vec<ReportFailureCondition>,
}

impl AssessmentReportPolicyOutcomeV1 {
    /// Encodes an outcome after independently reproducing its policy decision.
    ///
    /// # Errors
    /// Returns an error for a changed assessment, conflicting outcome, invalid
    /// policy/result or exceeded encoding bounds.
    pub fn to_bytes(&self, assessment: &PackageAssessmentV1) -> Result<Vec<u8>> {
        ensure!(
            *self == self.policy.evaluate(assessment)?,
            "report policy outcome does not reproduce"
        );
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "assessment report policy outcome")?;
        canonical::to_vec(&value)
    }
}
