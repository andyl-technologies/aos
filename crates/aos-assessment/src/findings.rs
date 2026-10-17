//! Exact source/query coverage and component-scoped advisory matching.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::{Context as _, Result};
use aos_contract::Sha256Digest;

use crate::advisory::{AdvisoryRecordV1, AffectedRange, RangeEvent};
use crate::aliases::AliasIndex;
use crate::input::{EvaluationData, ScanInputV1};
use crate::ranges::{Truth, affected_range, affected_version};
use crate::result::{Applicability, UpstreamFix, VULNERABILITY_FINDING_V1, VulnerabilityFinding};
use crate::scan_inventory::ComponentInstance;
use crate::security::SecurityIdentity;

pub(crate) struct ComponentFindings {
    pub complete: bool,
    pub unmapped: bool,
    pub unsupported: bool,
    pub stale: bool,
    pub failed: bool,
    pub reasons: Vec<String>,
    pub findings: Vec<VulnerabilityFinding>,
}

pub(crate) fn evaluate(
    component: &ComponentInstance,
    environment: &[ComponentInstance],
    input: &ScanInputV1,
    data: &EvaluationData,
    records: &BTreeMap<Sha256Digest, &AdvisoryRecordV1>,
    aliases: &AliasIndex,
) -> Result<ComponentFindings> {
    let mut result = ComponentFindings {
        complete: true,
        unmapped: false,
        unsupported: false,
        stale: false,
        failed: false,
        reasons: vec![],
        findings: vec![],
    };
    let mapped = component
        .security
        .identities
        .iter()
        .filter(|identity| !matches!(identity, SecurityIdentity::Unmapped { .. }))
        .collect::<Vec<_>>();
    if mapped.is_empty() || mapped.len() != component.security.identities.len() {
        result.unmapped = true;
        result.reasons.push("identity-unmapped".into());
    }
    if !matches!(
        crate::ranges::compare_versions(
            component.security.version_scheme,
            &component.current.comparison_version,
            &component.current.comparison_version
        ),
        Ok(Some(_))
    ) {
        result.unsupported = true;
        result.reasons.push("version-unsupported".into());
    }
    let sources = component
        .security
        .advisory_sources
        .iter()
        .map(|source| source.provider.as_str())
        .collect::<BTreeSet<_>>();
    if sources.is_empty()
        || data
            .policy
            .required_advisory_sources
            .iter()
            .any(|required| !sources.contains(required.as_str()))
    {
        result.failed = true;
        result.reasons.push("provider-unconfigured".into());
    }

    let mut eligible_records = BTreeSet::new();
    let snapshot = data
        .advisory_snapshot
        .as_ref()
        .context("vulnerability input lacks pinned snapshot")?;
    for mapping in &component.security.advisory_sources {
        if !matches!(mapping.provider.as_str(), "osv" | "nvd") {
            result.unsupported = true;
            result.reasons.push("provider-profile-unsupported".into());
            continue;
        }
        if !mapped
            .iter()
            .any(|identity| supported_source_identity(&mapping.provider, identity))
        {
            result.unsupported = true;
            result.reasons.push("provider-identity-unsupported".into());
            continue;
        }
        let projects = if let Some(project) = &mapping.project {
            vec![project.clone()]
        } else {
            mapped
                .iter()
                .filter(|identity| supported_source_identity(&mapping.provider, identity))
                .map(|identity| {
                    query_scope(
                        &mapping.provider,
                        identity,
                        &component.current.comparison_version,
                    )
                })
                .collect::<Result<Vec<_>>>()?
        };
        if projects.is_empty() {
            result.unsupported = true;
            result.reasons.push("provider-identity-unsupported".into());
        }
        for project in projects {
            let source = snapshot
                .sources
                .binary_search_by(|source| {
                    (source.provider.as_str(), source.project.as_str())
                        .cmp(&(mapping.provider.as_str(), project.as_str()))
                })
                .ok()
                .map(|index| &snapshot.sources[index]);
            let Some(source) = source else {
                result.failed = true;
                result.reasons.push("provider-unavailable".into());
                continue;
            };
            if !source.observation.coverage.is_complete() {
                result.failed = true;
                result.reasons.push("coverage-truncated".into());
            }
            if !source.observation.is_fresh_at(&input.evaluated_at)?
                || input
                    .evaluated_at
                    .elapsed_since(&source.observation.validated_at)?
                    > data.policy.advisory_max_age_seconds
            {
                result.stale = true;
                result.reasons.push("snapshot-stale".into());
            }
            // Positive retained claims remain usable after refresh failure/expiry.
            eligible_records.extend(&source.record_digests);
        }
    }
    let component_digest = component.digest()?;
    let mut findings = BTreeMap::<Sha256Digest, VulnerabilityFinding>::new();
    for record_digest in eligible_records {
        let record = records
            .get(&record_digest)
            .context("pinned advisory record is missing")?;
        if record.withdrawn.is_some() {
            continue;
        }
        let matched = match_record(component, environment, record)?;
        if matched == Truth::False {
            continue;
        }
        if matched == Truth::Unknown {
            result.unsupported = true;
            result.reasons.push("applicability-unsupported".into());
        }
        let advisory_ids = aliases
            .identities(&record.id)
            .context("advisory equivalence identity is missing")?;
        if advisory_ids.len() > 128 {
            anyhow::bail!("advisory equivalence exceeds the bounded finding profile");
        }
        let key = finding_key(component_digest, advisory_ids)?;
        let finding = findings.entry(key).or_insert_with(|| VulnerabilityFinding {
            finding_key: key,
            component_instance_digest: component_digest,
            component_ref: component.component_ref.clone(),
            advisory_ids: advisory_ids.to_vec(),
            advisory_record_digests: vec![],
            applicability: Applicability::Unknown,
            match_evidence: vec![],
            severity: vec![],
            fixes: vec![],
            exploit_signals: vec![],
            disposition_refs: vec![],
        });
        if matched == Truth::True {
            finding.applicability = Applicability::Affected;
        }
        finding.advisory_record_digests.push(record_digest);
        finding.match_evidence.push(format!(
            "{}:{}",
            record.provider,
            if matched == Truth::True {
                "exact-identity-supported-range"
            } else {
                "applicability-unsupported"
            }
        ));
        finding.severity.extend(record.severity.iter().cloned());
        if let Some(catalog) = &snapshot.exploit_catalog {
            finding.exploit_signals.extend(
                catalog
                    .records
                    .iter()
                    .filter(|signal| advisory_ids.binary_search(&signal.cve_id).is_ok())
                    .cloned(),
            );
        }
        finding
            .fixes
            .extend(fixes(component, record, record_digest)?);
        for disposition in &data.dispositions {
            if disposition.applies_at(component_digest, record_digest, &input.evaluated_at) {
                finding.disposition_refs.push(disposition.digest()?);
            }
        }
    }
    for finding in findings.values_mut() {
        finding.advisory_record_digests.sort();
        finding.advisory_record_digests.dedup();
        finding.match_evidence.sort();
        finding.match_evidence.dedup();
        finding.severity.sort();
        finding.severity.dedup();
        finding.fixes.sort();
        finding.fixes.dedup();
        finding.exploit_signals.sort();
        finding.exploit_signals.dedup();
        finding.disposition_refs.sort();
        finding.disposition_refs.dedup();
    }
    result.findings = findings.into_values().collect();
    result.reasons.sort();
    result.reasons.dedup();
    result.complete = result.reasons.is_empty();
    Ok(result)
}

fn match_record(
    component: &ComponentInstance,
    environment: &[ComponentInstance],
    record: &AdvisoryRecordV1,
) -> Result<Truth> {
    if let Some(configuration) = &record.configuration {
        return Ok(configuration.evaluate(component, environment)?.affected);
    }
    let mut matched = Truth::False;
    for product in &record.affected {
        if component
            .security
            .identities
            .iter()
            .any(|identity| identities_match(identity, &product.identity))
        {
            matched = matched.or(affected_version(
                product,
                &component.current.comparison_version,
                component.security.version_scheme,
            )?);
        }
    }
    Ok(matched)
}

fn fixes(
    component: &ComponentInstance,
    record: &AdvisoryRecordV1,
    record_digest: Sha256Digest,
) -> Result<Vec<UpstreamFix>> {
    let mut fixes = Vec::new();
    for product in &record.affected {
        if !component
            .security
            .identities
            .iter()
            .any(|identity| identities_match(identity, &product.identity))
        {
            continue;
        }
        for range in &product.ranges {
            let mut introduced = None;
            for event in &range.events {
                match event {
                    RangeEvent::Introduced(version) => introduced = Some(version),
                    RangeEvent::Fixed(version) => {
                        if let Some(start) = introduced.take() {
                            let interval = AffectedRange {
                                kind: range.kind,
                                repository: range.repository.clone(),
                                events: vec![RangeEvent::Introduced(start.clone()), event.clone()],
                            };
                            if affected_range(
                                &interval,
                                &component.current.comparison_version,
                                component.security.version_scheme,
                            )? == Truth::True
                            {
                                fixes.push(UpstreamFix {
                                    advisory_record_digest: record_digest,
                                    version: version.clone(),
                                });
                            }
                        }
                    }
                    RangeEvent::LastAffected(_) | RangeEvent::Limit(_) => introduced = None,
                }
            }
        }
    }
    Ok(fixes)
}

/// Computes the stable component/equivalent-ID/profile key of a raw finding.
///
/// # Errors
///
/// Returns an error when identifiers cannot be canonically encoded.
pub fn finding_key(component: Sha256Digest, ids: &[String]) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical(
        VULNERABILITY_FINDING_V1,
        &(component, ids, "vulnerabilities"),
    )
}

/// Computes an exact provider/product/version query scope without database IDs.
///
/// # Errors
///
/// Returns an error for invalid identity structure or canonical serialization.
pub fn query_scope(provider: &str, identity: &SecurityIdentity, version: &str) -> Result<String> {
    identity.validate()?;
    Ok(
        Sha256Digest::of_canonical("aos.advisory-query/v1", &(provider, identity, version))?
            .to_string(),
    )
}

fn supported_source_identity(provider: &str, identity: &SecurityIdentity) -> bool {
    match provider {
        "osv" => match identity {
            SecurityIdentity::Ecosystem { ecosystem, .. } => matches!(
                ecosystem.as_str(),
                "crates.io" | "Go" | "npm" | "PyPI" | "Maven" | "OSS-Fuzz" | "Linux"
            ),
            SecurityIdentity::Purl { value } => purl_ecosystem(value).is_some(),
            SecurityIdentity::Git { .. } => true,
            _ => false,
        },
        "nvd" => matches!(identity, SecurityIdentity::Cpe { .. }),
        _ => false,
    }
}

fn identities_match(left: &SecurityIdentity, right: &SecurityIdentity) -> bool {
    match (left, right) {
        (
            SecurityIdentity::Ecosystem {
                ecosystem: left_ecosystem,
                name: left_name,
            },
            SecurityIdentity::Ecosystem {
                ecosystem: right_ecosystem,
                name: right_name,
            },
        ) => left_ecosystem == right_ecosystem && left_name == right_name,
        (SecurityIdentity::Purl { value: left }, SecurityIdentity::Purl { value: right }) => {
            let (Ok(mut left), Ok(mut right)) = (
                packageurl::PackageUrl::from_str(left),
                packageurl::PackageUrl::from_str(right),
            ) else {
                return false;
            };
            left.without_version();
            right.without_version();
            left == right
        }
        (
            SecurityIdentity::Git {
                repository: left, ..
            },
            SecurityIdentity::Git {
                repository: right, ..
            },
        ) => left == right,
        (SecurityIdentity::Purl { value }, SecurityIdentity::Ecosystem { ecosystem, name })
        | (SecurityIdentity::Ecosystem { ecosystem, name }, SecurityIdentity::Purl { value }) => {
            purl_ecosystem(value).is_some_and(|(mapped_ecosystem, mapped_name)| {
                ecosystem == mapped_ecosystem && name == &mapped_name
            })
        }
        _ => false,
    }
}

fn purl_ecosystem(value: &str) -> Option<(&'static str, String)> {
    let purl = packageurl::PackageUrl::from_str(value).ok()?;
    if !purl.qualifiers().is_empty() || purl.subpath().is_some() {
        return None;
    }
    match purl.ty() {
        "cargo" if purl.namespace().is_none() => Some(("crates.io", purl.name().into())),
        "pypi" if purl.namespace().is_none() => Some(("PyPI", purl.name().into())),
        "npm" => Some((
            "npm",
            purl.namespace().map_or_else(
                || purl.name().into(),
                |namespace| format!("{namespace}/{}", purl.name()),
            ),
        )),
        "golang" => Some((
            "Go",
            purl.namespace().map_or_else(
                || purl.name().into(),
                |namespace| format!("{namespace}/{}", purl.name()),
            ),
        )),
        "maven" => purl
            .namespace()
            .map(|namespace| ("Maven", format!("{namespace}:{}", purl.name()))),
        _ => None,
    }
}
