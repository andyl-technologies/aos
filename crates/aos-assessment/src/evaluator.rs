//! Pure shared assessment evaluation over an explicitly frozen evidence closure.
//!
//! Every result is derived from supplied objects and explicit evaluation time.
//! No database head, network fallback or wall-clock read participates in matching.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};

use crate::aliases::equivalence;
use crate::definition::PackageScanDefinitionV1;
use crate::input::{EvaluationData, Profile, ScanInputV1};
use crate::result::{
    Diagnostic, PACKAGE_ASSESSMENT_V1, PackageAssessmentV1, ProfileCoverage, SubjectResult,
};
use crate::scan_inventory::{ComponentInstance, RelationshipKind};
use crate::security::CoverageState;

/// Evaluates exact inputs with identical semantic behavior in every runtime.
///
/// # Errors
///
/// Returns an error for missing/conflicting objects, changed input identities,
/// invalid graphs, unsupported engine profiles or excessive output scope. Source
/// uncertainty is represented in coverage/findings rather than a clean result.
pub fn evaluate(input: &ScanInputV1, data: &EvaluationData) -> Result<PackageAssessmentV1> {
    if data.freeze_selected(
        input.profiles.clone(),
        input.subject_refs.clone(),
        input.evaluated_at.clone(),
    )? != *input
    {
        bail!("frozen assessment input does not match its supplied evidence closure");
    }
    let definitions = data
        .definitions
        .iter()
        .map(|definition| Ok((definition.digest()?, definition)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let aliases = equivalence(&data.advisories);
    let records = data
        .advisories
        .iter()
        .map(|record| Ok((record.digest()?, record)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut diagnostics = BTreeSet::new();
    let mut subject_results = Vec::new();
    let mut component_budget = 0;
    let mut finding_budget = 0;
    let graph = ScopeGraph::new(data)?;
    let upstream = data
        .upstream
        .iter()
        .map(|binding| (binding.component_ref.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    let selected = input
        .subject_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for subject in data
        .inventory
        .subjects
        .iter()
        .filter(|subject| selected.contains(subject.subject_ref.as_str()))
    {
        let scope = graph.components(&subject.subject_ref)?;
        component_budget += scope.len();
        if component_budget > 100_000 {
            bail!("assessment aggregate component result scope exceeds budget");
        }
        let environment = scope
            .iter()
            .map(|component| (*component).clone())
            .collect::<Vec<_>>();
        let mut result = SubjectResult {
            subject_ref: subject.subject_ref.clone(),
            versions: vec![],
            findings: vec![],
            coverage: vec![],
        };
        for profile in &input.profiles {
            let mut coverage = ProfileCoverage {
                profile: *profile,
                state: CoverageState::Complete,
                counts: Default::default(),
                reasons: vec![],
            };
            for component in &scope {
                coverage.counts.declared += 1;
                let definition = definitions
                    .get(&component.scan_definition_digest)
                    .context("component definition is missing")?;
                match profile {
                    Profile::Updates => {
                        let (version, reasons) = crate::version::evaluate(
                            component,
                            definition,
                            input,
                            data,
                            upstream.get(component.component_ref.as_str()).copied(),
                        )?;
                        if reasons.is_empty() {
                            coverage.counts.evaluated += 1;
                        }
                        coverage.counts.failed += u64::from(reasons.iter().any(|reason| {
                            matches!(
                                reason.as_str(),
                                "provider-unavailable" | "coverage-truncated"
                            )
                        }));
                        coverage.counts.stale +=
                            u64::from(reasons.iter().any(|reason| reason == "snapshot-stale"));
                        coverage.counts.unsupported +=
                            u64::from(reasons.iter().any(|reason| reason == "version-unsupported"));
                        coverage.reasons.extend(reasons);
                        result.versions.push(version);
                    }
                    Profile::Vulnerabilities => {
                        let component_result = crate::findings::evaluate(
                            component,
                            &environment,
                            input,
                            data,
                            &records,
                            &aliases,
                        )?;
                        coverage.counts.evaluated += u64::from(component_result.complete);
                        coverage.counts.unmapped += u64::from(component_result.unmapped);
                        coverage.counts.unsupported += u64::from(component_result.unsupported);
                        coverage.counts.stale += u64::from(component_result.stale);
                        coverage.counts.failed += u64::from(component_result.failed);
                        coverage.reasons.extend(component_result.reasons);
                        finding_budget += component_result.findings.len();
                        if finding_budget > 100_000 {
                            bail!("assessment finding result scope exceeds budget");
                        }
                        result.findings.extend(component_result.findings);
                    }
                    Profile::LicenseSignals => {
                        coverage.counts.failed += 1;
                        coverage
                            .reasons
                            .push("license-observations-unavailable".into());
                    }
                }
            }
            if scope.is_empty() {
                coverage
                    .reasons
                    .push("component-inventory-unavailable".into());
            }
            if *profile == Profile::Vulnerabilities
                && data.policy.require_dependency_coverage
                && (data.inventory.coverage.state != CoverageState::Complete
                    || scope.iter().any(|component| {
                        component.security.dependency_coverage.state != CoverageState::Complete
                    }))
            {
                coverage
                    .reasons
                    .push("dependency-coverage-incomplete".into());
            }
            coverage.reasons.sort();
            coverage.reasons.dedup();
            if !coverage.reasons.is_empty() {
                coverage.state = if coverage.counts.evaluated > 0
                    || !result.findings.is_empty()
                    || result
                        .versions
                        .iter()
                        .any(|version| version.latest_known.is_some())
                {
                    CoverageState::Partial
                } else {
                    CoverageState::Unknown
                };
                for reason in &coverage.reasons {
                    diagnostics.insert(Diagnostic {
                        code: reason.clone(),
                        subject_ref: subject.subject_ref.clone(),
                        summary: diagnostic_summary(reason).into(),
                    });
                }
            }
            result.coverage.push(coverage);
        }
        result
            .versions
            .sort_by(|left, right| left.component_ref.cmp(&right.component_ref));
        result.findings.sort_by_key(|finding| finding.finding_key);
        subject_results.push(result);
    }
    let coverage = if subject_results.iter().all(|subject| {
        subject
            .coverage
            .iter()
            .all(|coverage| coverage.state == CoverageState::Complete)
    }) {
        CoverageState::Complete
    } else if subject_results.iter().any(|subject| {
        subject
            .coverage
            .iter()
            .any(|coverage| coverage.state != CoverageState::Unknown)
    }) {
        CoverageState::Partial
    } else {
        CoverageState::Unknown
    };
    let assessment = PackageAssessmentV1 {
        schema: PACKAGE_ASSESSMENT_V1.into(),
        input_digest: input.digest()?,
        subject_results,
        diagnostics: diagnostics.into_iter().collect(),
        coverage,
    };
    assessment.digest()?;
    Ok(assessment)
}

/// Indexes exact runtime/containment scope while excluding build-only dependencies.
pub struct ScopeGraph<'a> {
    subjects: BTreeSet<&'a str>,
    components: BTreeMap<&'a str, &'a ComponentInstance>,
    edges: BTreeMap<&'a str, BTreeSet<&'a str>>,
}

impl<'a> ScopeGraph<'a> {
    /// Builds one reusable traversal index from the validated inventory graph.
    ///
    /// # Errors
    /// Returns an error for invalid inventory, unresolved edges or graph bounds.
    pub fn new(data: &'a EvaluationData) -> Result<Self> {
        data.inventory.validate()?;
        let subjects = data
            .inventory
            .subjects
            .iter()
            .map(|subject| subject.subject_ref.as_str())
            .collect();
        let components = data
            .inventory
            .components
            .iter()
            .map(|component| (component.component_ref.as_str(), component))
            .collect();
        let mut edges = BTreeMap::<&str, BTreeSet<&str>>::new();
        for subject in &data.inventory.subjects {
            edges
                .entry(&subject.subject_ref)
                .or_default()
                .extend(subject.member_refs.iter().map(String::as_str));
        }
        for component in &data.inventory.components {
            edges
                .entry(&component.subject_ref)
                .or_default()
                .insert(&component.component_ref);
        }
        for edge in &data.inventory.relationships {
            if matches!(
                edge.kind,
                RelationshipKind::Contains | RelationshipKind::RuntimeDependsOn
            ) {
                edges
                    .entry(&edge.from_ref)
                    .or_default()
                    .insert(&edge.to_ref);
            }
        }
        Ok(Self {
            subjects,
            components,
            edges,
        })
    }

    /// Returns exact contained/runtime component instances in canonical reference order.
    ///
    /// # Errors
    /// Returns an error for an unknown subject or excessive dependency traversal.
    pub fn components(&self, subject: &str) -> Result<Vec<&'a ComponentInstance>> {
        if !self.subjects.contains(subject) {
            bail!("assessment subject is absent from the inventory graph");
        }
        let mut pending = vec![subject];
        let mut visited = BTreeSet::new();
        let mut components = BTreeMap::new();
        while let Some(reference) = pending.pop() {
            if !visited.insert(reference) {
                continue;
            }
            if visited.len() > 110_000 {
                bail!("assessment dependency traversal exceeds scope bound");
            }
            if let Some(component) = self.components.get(reference) {
                components.insert(reference, *component);
            }
            if let Some(targets) = self.edges.get(reference) {
                pending.extend(targets);
            }
        }
        Ok(components.into_values().collect())
    }
}

fn diagnostic_summary(code: &str) -> &'static str {
    match code {
        "identity-unmapped" => "No admitted advisory identity is available for this component.",
        "snapshot-stale" => "Required evidence has expired under the pinned freshness policy.",
        "version-unsupported" => "The declared version scheme lacks supported comparison evidence.",
        "provider-unavailable" => "Required provider evidence is missing or unavailable.",
        "coverage-truncated" => "Provider limits prevented a completeness proof.",
        "dependency-coverage-incomplete" => {
            "The included dependency inventory lacks complete evidence."
        }
        _ => "Required assessment scope could not be established from the pinned evidence.",
    }
}

/// Resolves a component's exact declaration after frozen input validation.
pub(crate) fn declaration<'a>(
    component: &ComponentInstance,
    definition: &'a PackageScanDefinitionV1,
) -> Result<&'a crate::definition::ScanComponent> {
    definition
        .components
        .iter()
        .find(|declared| declared.component_id == component.component_id)
        .context("component scan declaration is missing")
}
