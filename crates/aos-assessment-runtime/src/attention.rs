//! Deterministic attention projection from reproduced assessment results.
//!
//! Subject/artifact context partitions every issue. Source/query keys remain
//! stable across advisory revisions, allowing complete fresh evidence to resolve
//! prior issues while stale or unrelated queries retain uncertainty.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_assessment::evaluator::ScopeGraph;
use aos_assessment::input::{EvaluationData, Profile, ScanInputV1};
use aos_assessment::result::{Applicability, PackageAssessmentV1, VersionDecision};
use aos_assessment::security::CoverageState;
use aos_contract::Sha256Digest;
use serde_json::json;

use crate::alerts::{IssueFamily, IssueObservation, ResolutionProof};

/// Carries attention observations and exact resolution proofs for one subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAttention {
    /// Exact portable subject within the selected immutable inventory.
    pub subject_ref: String,
    /// Independent observations in canonical issue-key order.
    pub issues: Vec<IssueObservation>,
    /// Fresh complete resolution scopes; partial coverage produces no proof.
    pub proofs: Vec<ResolutionProof>,
}

/// Projects a reproduced assessment into scoped durable attention input.
///
/// The journal must reproduce the supplied assessment before committing these
/// projections. Digests validate associations rather than source/review authority.
/// Related and upstream advisory links are excluded from vulnerability lineage.
///
/// # Errors
/// Returns an error for mismatched scope/input, unsupported result associations,
/// missing source support, invalid graph data or excessive attention output.
pub fn project(
    input: &ScanInputV1,
    data: &EvaluationData,
    assessment: &PackageAssessmentV1,
) -> Result<Vec<SubjectAttention>> {
    input.validate()?;
    assessment.validate()?;
    if assessment.input_digest != input.digest()?
        || data.inventory.digest()? != input.inventory_digest
        || data.policy.digest()? != input.policy_digest
    {
        bail!("attention input differs from the exact assessment closure");
    }
    let graph = ScopeGraph::new(data)?;
    let subjects = data
        .inventory
        .subjects
        .iter()
        .map(|subject| (subject.subject_ref.as_str(), subject))
        .collect::<BTreeMap<_, _>>();
    let upstream = data
        .upstream
        .iter()
        .map(|binding| (binding.component_ref.as_str(), &binding.observation))
        .collect::<BTreeMap<_, _>>();
    let mut record_sources = BTreeMap::<_, BTreeSet<_>>::new();
    let mut fresh_sources = BTreeSet::new();
    if let Some(snapshot) = &data.advisory_snapshot {
        for source in &snapshot.sources {
            let key = source_key(&source.provider, &source.project)?;
            for digest in &source.record_digests {
                record_sources.entry(*digest).or_default().insert(key);
            }
            if source.observation.coverage.is_complete()
                && source.observation.is_fresh_at(&input.evaluated_at)?
                && input
                    .evaluated_at
                    .elapsed_since(&source.observation.validated_at)?
                    <= data.policy.advisory_max_age_seconds
            {
                fresh_sources.insert(key);
            }
        }
    }
    let mut output = Vec::with_capacity(assessment.subject_results.len());
    let mut issue_count = 0;
    let mut proof_count = 0;
    for result in &assessment.subject_results {
        if input
            .subject_refs
            .binary_search(&result.subject_ref)
            .is_err()
        {
            bail!("attention subject is outside the exact frozen selector");
        }
        let subject = subjects
            .get(result.subject_ref.as_str())
            .context("attention subject is absent")?;
        let subject_digest =
            Sha256Digest::of_canonical("aos.assessment-subject-context/v1", subject)?;
        let components = graph
            .components(&result.subject_ref)?
            .into_iter()
            .map(|component| (component.component_ref.as_str(), component))
            .collect::<BTreeMap<_, _>>();
        let coverage = result
            .coverage
            .iter()
            .map(|coverage| (coverage.profile, coverage))
            .collect::<BTreeMap<_, _>>();
        let mut projected = SubjectAttention {
            subject_ref: result.subject_ref.clone(),
            issues: vec![],
            proofs: vec![],
        };
        for profile in &input.profiles {
            let state = coverage
                .get(profile)
                .context("assessment lacks a requested attention profile")?;
            let context = issue_context(subject_digest, None, *profile)?;
            if state.state == CoverageState::Complete {
                projected.proofs.push(ResolutionProof {
                    context_digest: context,
                    profile: *profile,
                    checked_source_keys: vec![],
                });
            } else {
                projected.issues.push(IssueObservation {
                    issue_key: issue_key(context, IssueFamily::Coverage, &["coverage".into()])?,
                    context_digest: context,
                    family: IssueFamily::Coverage,
                    profile: *profile,
                    lineage_ids: vec!["coverage".into()],
                    source_keys: vec![],
                    material_digest: Sha256Digest::of_canonical(
                        "aos.assessment-issue-material/v1",
                        state,
                    )?,
                    uncertain: true,
                });
            }
        }
        for version in &result.versions {
            let component = components
                .get(version.component_ref.as_str())
                .context("update attention component is outside subject scope")?;
            let context =
                issue_context(subject_digest, Some(component.digest()?), Profile::Updates)?;
            let keys = upstream
                .get(version.component_ref.as_str())
                .map(|observation| {
                    source_key(&observation.provider, &observation.project).map(|key| vec![key])
                })
                .transpose()?
                .unwrap_or_default();
            if coverage
                .get(&Profile::Updates)
                .is_some_and(|value| value.state == CoverageState::Complete)
                && !keys.is_empty()
            {
                projected.proofs.push(ResolutionProof {
                    context_digest: context,
                    profile: Profile::Updates,
                    checked_source_keys: keys.clone(),
                });
            }
            if version.decision == VersionDecision::UpdateAvailable {
                let lineage = vec!["maintained-stream".into()];
                projected.issues.push(IssueObservation {
                    issue_key: issue_key(context, IssueFamily::PackageUpdate, &lineage)?, context_digest: context,
                    family: IssueFamily::PackageUpdate, profile: Profile::Updates, lineage_ids: lineage, source_keys: keys,
                    material_digest: Sha256Digest::of_canonical("aos.assessment-issue-material/v1", &json!({
                        "current":version.current, "eligible":version.eligible, "decision":version.decision,
                    }))?, uncertain: false,
                });
            }
        }
        if coverage
            .get(&Profile::Vulnerabilities)
            .is_some_and(|value| value.state == CoverageState::Complete)
        {
            for component in components.values() {
                let keys = component_source_keys(component)?;
                if !keys.is_empty() && keys.iter().all(|key| fresh_sources.contains(key)) {
                    projected.proofs.push(ResolutionProof {
                        context_digest: issue_context(
                            subject_digest,
                            Some(component.digest()?),
                            Profile::Vulnerabilities,
                        )?,
                        profile: Profile::Vulnerabilities,
                        checked_source_keys: keys.into_iter().collect(),
                    });
                }
            }
        }
        for finding in &result.findings {
            let component = components
                .get(finding.component_ref.as_str())
                .context("vulnerability attention component is outside subject scope")?;
            if component.digest()? != finding.component_instance_digest {
                bail!("finding attention changed component identity");
            }
            let context = issue_context(
                subject_digest,
                Some(finding.component_instance_digest),
                Profile::Vulnerabilities,
            )?;
            let keys = finding
                .advisory_record_digests
                .iter()
                .filter_map(|digest| record_sources.get(digest))
                .flat_map(|keys| keys.iter().copied())
                .collect::<BTreeSet<_>>();
            let supported = component_source_keys(component)?;
            let keys = keys
                .intersection(&supported)
                .copied()
                .collect::<BTreeSet<_>>();
            let fixes = finding
                .fixes
                .iter()
                .map(|fix| fix.version.as_str())
                .collect::<BTreeSet<_>>();
            projected.issues.push(IssueObservation {
                issue_key: issue_key(context, IssueFamily::Vulnerability, &finding.advisory_ids)?, context_digest: context,
                family: IssueFamily::Vulnerability, profile: Profile::Vulnerabilities, lineage_ids: finding.advisory_ids.clone(),
                source_keys: keys.into_iter().collect(), uncertain: finding.applicability != Applicability::Affected
                    || !coverage.get(&Profile::Vulnerabilities).is_some_and(|value| value.state == CoverageState::Complete),
                material_digest: Sha256Digest::of_canonical("aos.assessment-issue-material/v1", &json!({
                    "applicability":finding.applicability, "severity":finding.severity, "fixes":fixes,
                    "knownExploitation":!finding.exploit_signals.is_empty(), "dispositions":finding.disposition_refs,
                }))?,
            });
        }
        projected.issues.sort_by_key(|issue| issue.issue_key);
        for issue in &projected.issues {
            issue.validate()?;
        }
        projected
            .proofs
            .sort_by_key(|proof| (proof.context_digest, proof.profile));
        if projected.proofs.windows(2).any(|pair| {
            (pair[0].context_digest, pair[0].profile) == (pair[1].context_digest, pair[1].profile)
        }) {
            bail!("attention projection contains duplicate resolution scope");
        }
        issue_count += projected.issues.len();
        proof_count += projected.proofs.len();
        if issue_count > 100_000 || proof_count > 100_000 {
            bail!("assessment attention projection exceeds bounded scope");
        }
        output.push(projected);
    }
    if output.len() != input.subject_refs.len() {
        bail!("attention projection omits a selected subject");
    }
    Ok(output)
}

/// Computes a stable source/query key independent of response revision and age.
///
/// # Errors
/// Returns an error for empty, oversized or control-bearing source identities.
pub fn source_key(provider: &str, project: &str) -> Result<Sha256Digest> {
    if provider.is_empty()
        || provider.len() > 128
        || project.is_empty()
        || project.len() > 1024
        || provider
            .chars()
            .chain(project.chars())
            .any(char::is_control)
    {
        bail!("attention source identity is invalid");
    }
    Sha256Digest::of_canonical("aos.assessment-source-key/v1", &(provider, project))
}

fn issue_context(
    subject: Sha256Digest,
    component: Option<Sha256Digest>,
    profile: Profile,
) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical(
        "aos.assessment-issue-context/v1",
        &(subject, component, profile),
    )
}

fn issue_key(
    context: Sha256Digest,
    family: IssueFamily,
    lineage: &[String],
) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical("aos.assessment-issue-key/v1", &(context, family, lineage))
}

fn component_source_keys(
    component: &aos_assessment::scan_inventory::ComponentInstance,
) -> Result<BTreeSet<Sha256Digest>> {
    let mut keys = BTreeSet::new();
    for mapping in &component.security.advisory_sources {
        if let Some(project) = &mapping.project {
            keys.insert(source_key(&mapping.provider, project)?);
        } else {
            for identity in &component.security.identities {
                if let Ok(project) = aos_assessment::findings::query_scope(
                    &mapping.provider,
                    identity,
                    &component.current.comparison_version,
                ) {
                    keys.insert(source_key(&mapping.provider, &project)?);
                }
            }
        }
    }
    Ok(keys)
}
