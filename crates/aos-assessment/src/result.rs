//! Canonical assessment findings, profile coverage and presentation-neutral data.
//!
//! Empty finding lists and successful operations do not imply complete coverage.
//! Results reference one frozen input; runtime IDs and progress live elsewhere.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::advisory::{AdvisorySeverity, KnownExploit};
use crate::decision::DiscoveryDecision;
use crate::discovery::CandidateRejection;
use crate::input::Profile;
use crate::inventory::ComponentVersion;
use crate::security::CoverageState;
use crate::validation::{decode, digest, sorted, text};

/// Identifies a canonical package-assessment result.
pub const PACKAGE_ASSESSMENT_V1: &str = "aos.package-assessment/v1";

/// Identifies a component/advisory finding's stable key domain.
pub const VULNERABILITY_FINDING_V1: &str = "aos.vulnerability-finding/v1";

/// Separates maintained-stream evidence from package controller authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionDecision {
    /// Complete fresh evidence establishes no eligible newer version.
    Current,
    /// Complete fresh evidence establishes an eligible newer version.
    UpdateAvailable,
    /// A newer candidate is waiting for its declared minimum age.
    Stabilizing,
    /// The package requires explicit human selection.
    Manual,
    /// Package policy intentionally prevents automatic selection.
    Frozen,
    /// Required evidence, ordering or freshness is insufficient.
    Unknown,
    /// Conflicting immutable identities require review.
    Quarantined,
}

impl From<DiscoveryDecision> for VersionDecision {
    fn from(decision: DiscoveryDecision) -> Self {
        match decision {
            DiscoveryDecision::Current => Self::Current,
            DiscoveryDecision::UpdateAvailable => Self::UpdateAvailable,
            DiscoveryDecision::Unknown => Self::Unknown,
            DiscoveryDecision::Quarantined => Self::Quarantined,
        }
    }
}

/// Records a version decision without granting source-edit authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VersionResult {
    /// Exact component within the admitted inventory.
    pub component_ref: String,
    /// Exact current upstream/comparison version.
    pub current: ComponentVersion,
    /// Shared selection decision under the maintained stream.
    pub decision: VersionDecision,
    /// Latest observed upstream candidate, independent of eligibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_known: Option<ComponentVersion>,
    /// Marks latest-known evidence as provisional when enumeration is incomplete.
    pub latest_known_provisional: bool,
    /// Policy-eligible newer release, if established by complete fresh evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligible: Option<ComponentVersion>,
    /// Exact upstream evidence identities, sorted and unique.
    pub observation_digests: Vec<Sha256Digest>,
    /// Shared rejection reasons, preserved in deterministic candidate order.
    pub rejected: Vec<CandidateRejection>,
}

/// Classifies what supported advisory evidence establishes for a component.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Applicability {
    /// Exact admitted identity and supported range/configuration match.
    Affected,
    /// Retains a positive product association with incomplete applicability facts.
    PotentiallyAffected,
    /// Retains an unresolved relevant source claim under unsupported semantics.
    Unknown,
}

/// Retains a source-attributed upstream fix without asserting AOS publication.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpstreamFix {
    /// Exact source revision that identifies this fix.
    pub advisory_record_digest: Sha256Digest,
    /// Provider-native fixed version/commit identity.
    pub version: String,
}

/// Preserves a raw source match independently from reviewed dispositions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VulnerabilityFinding {
    /// Stable component/equivalence/profile identity for alert continuity.
    pub finding_key: Sha256Digest,
    /// Exact component instance including artifact/configuration/patch binding.
    pub component_instance_digest: Sha256Digest,
    /// Portable component reference used for readable reports.
    pub component_ref: String,
    /// Sorted equivalent advisory IDs; related/upstream IDs are never aliases.
    pub advisory_ids: Vec<String>,
    /// Exact sorted source record revisions supporting the raw match.
    pub advisory_record_digests: Vec<Sha256Digest>,
    /// Explicit match conclusion, separate from severity or exploitation.
    pub applicability: Applicability,
    /// Sorted source/comparator proof classes used by this conclusion.
    pub match_evidence: Vec<String>,
    /// Source-attributed original severity entries, sorted and unique.
    pub severity: Vec<AdvisorySeverity>,
    /// Source-attributed upstream fixes; an empty list means no known fix evidence.
    pub fixes: Vec<UpstreamFix>,
    /// Source-attributed known exploitation; absence makes no opposite claim.
    pub exploit_signals: Vec<KnownExploit>,
    /// Applicable exact reviewed statements; these never remove the raw match.
    pub disposition_refs: Vec<Sha256Digest>,
}

/// Counts disjoint component outcomes while preserving overlapping limitations.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CoverageCounts {
    /// Unique declared components in this subject's checked scope.
    pub declared: u64,
    /// Unique components with complete fresh required-source evidence.
    pub evaluated: u64,
    /// Unique components without a supported exact advisory identity.
    pub unmapped: u64,
    /// Unique components containing unsupported required matching constructs.
    pub unsupported: u64,
    /// Unique components with expired required-source evidence.
    pub stale: u64,
    /// Unique components with missing/failed/truncated required-source evidence.
    pub failed: u64,
}

/// Preserves independent source/profile completeness rather than a clean boolean.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProfileCoverage {
    /// Independently evaluated profile.
    pub profile: Profile,
    /// Complete, useful-but-partial or wholly unknown evidence.
    pub state: CoverageState,
    /// Unique component counts and visible limitations.
    pub counts: CoverageCounts,
    /// Sorted stable limitation codes.
    pub reasons: Vec<String>,
}

/// Describes one bounded actionable limitation without persisting provider errors.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Diagnostic {
    /// Stable machine-readable reason.
    pub code: String,
    /// Portable subject reference.
    pub subject_ref: String,
    /// Sanitized short explanation.
    pub summary: String,
}

/// Reports exact component decisions and independent coverage for one subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubjectResult {
    /// Portable subject identity.
    pub subject_ref: String,
    /// Component decisions sorted by component reference.
    pub versions: Vec<VersionResult>,
    /// Raw findings sorted by stable finding key.
    pub findings: Vec<VulnerabilityFinding>,
    /// Requested profile coverage sorted by profile.
    pub coverage: Vec<ProfileCoverage>,
}

/// Binds canonical findings and diagnostics to one immutable semantic input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageAssessmentV1 {
    /// Exact closed result schema.
    pub schema: String,
    /// Exact validated frozen input; evaluation time is retained there.
    pub input_digest: Sha256Digest,
    /// Results strictly ordered by portable subject identity.
    pub subject_results: Vec<SubjectResult>,
    /// Sorted stable sanitized diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Overall completeness across all requested subjects/profiles.
    pub coverage: CoverageState,
}

impl PackageAssessmentV1 {
    /// Validates canonical ordering, counts and bounded result structure.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, excessive/duplicate scope,
    /// inconsistent complete coverage, invalid identifiers or unordered sets.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_ASSESSMENT_V1
            || self.subject_results.is_empty()
            || self.subject_results.len() > 10_000
            || self.diagnostics.len() > 100_000
        {
            bail!("invalid package assessment schema or result scope");
        }
        sorted(&self.diagnostics, "assessment diagnostics")?;
        for diagnostic in &self.diagnostics {
            text(&diagnostic.code, 128, "diagnostic code")?;
            text(&diagnostic.subject_ref, 128, "diagnostic subject")?;
            text(&diagnostic.summary, 4096, "diagnostic summary")?;
        }
        if self.coverage == CoverageState::Complete
            && self.subject_results.iter().any(|subject| {
                subject
                    .coverage
                    .iter()
                    .any(|coverage| coverage.state != CoverageState::Complete)
            })
        {
            bail!("assessment overall completeness differs from profile coverage");
        }
        let mut prior = None;
        for subject in &self.subject_results {
            text(&subject.subject_ref, 128, "assessment subject")?;
            if prior.is_some_and(|previous| previous >= &subject.subject_ref) {
                bail!("assessment subjects must be sorted and unique");
            }
            prior = Some(&subject.subject_ref);
            if subject.versions.len() > 100_000
                || subject.findings.len() > 100_000
                || subject.coverage.is_empty()
                || subject.coverage.len() > 3
            {
                bail!("assessment subject exceeds result scope");
            }
            if subject
                .versions
                .windows(2)
                .any(|pair| pair[0].component_ref >= pair[1].component_ref)
                || subject
                    .findings
                    .windows(2)
                    .any(|pair| pair[0].finding_key >= pair[1].finding_key)
                || subject
                    .coverage
                    .windows(2)
                    .any(|pair| pair[0].profile >= pair[1].profile)
            {
                bail!("assessment subject results must be sorted and unique");
            }
            for coverage in &subject.coverage {
                sorted(&coverage.reasons, "coverage limitation reasons")?;
                if coverage.counts.evaluated > coverage.counts.declared
                    || (coverage.state == CoverageState::Complete
                        && (coverage.counts.evaluated != coverage.counts.declared
                            || !coverage.reasons.is_empty()))
                {
                    bail!("assessment profile makes an inconsistent coverage claim");
                }
            }
            for finding in &subject.findings {
                if finding.advisory_ids.len() > 128
                    || finding.advisory_record_digests.len() > 128
                    || finding.advisory_ids.is_empty()
                    || finding.advisory_record_digests.is_empty()
                {
                    bail!("assessment finding lacks exact source support");
                }
                sorted(&finding.advisory_ids, "finding equivalent advisory IDs")?;
                if finding.finding_key
                    != crate::findings::finding_key(
                        finding.component_instance_digest,
                        &finding.advisory_ids,
                    )?
                {
                    bail!("finding key differs from its exact component/advisory scope");
                }
                sorted(
                    &finding.advisory_record_digests,
                    "finding advisory revisions",
                )?;
                sorted(&finding.match_evidence, "finding match evidence")?;
                sorted(&finding.severity, "finding severity")?;
                sorted(&finding.fixes, "finding upstream fixes")?;
                sorted(&finding.exploit_signals, "finding exploitation assertions")?;
                sorted(&finding.disposition_refs, "finding dispositions")?;
            }
        }
        Ok(())
    }

    /// Computes the domain-separated canonical assessment identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid result structure or canonical resource bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(PACKAGE_ASSESSMENT_V1, self)
    }

    /// Decodes a bounded canonical result without authorizing supplied evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/ambiguous/incompatible data or result bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let assessment: Self = decode(bytes, "package assessment")?;
        assessment.validate()?;
        Ok(assessment)
    }
}
